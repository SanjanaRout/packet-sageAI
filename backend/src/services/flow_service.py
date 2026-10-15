from __future__ import annotations

import asyncio
import csv
import io
import logging
import os
from pathlib import Path
import shutil
import tempfile
import uuid
from typing import Any

import numpy as np
import pandas as pd
from fastapi import HTTPException, UploadFile, status


from core.config import settings
from core.database import mongodb
from schemas.flow import UploadResponse
from services.model_service import ModelService

logger = logging.getLogger("packet_sage")


def _find_column(candidates: list[str], available_cols: set[str]) -> str | None:
    for candidate in candidates:
        if candidate in available_cols:
            return candidate
    return None


def score_chunk_sync(
    chunk_df: pd.DataFrame,
    features: list[str],
    model: Any,
    threshold: float,
    novelty_model: Any,
    novelty_medians: dict[str, float],
    novelty_threshold: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """
    Synchronous CPU-bound scoring.
    Returns:
        invalid_mask: np.ndarray (bool)
        scores: np.ndarray (float, NaN for invalid)
        labels: np.ndarray (str: "benign", "suspicious", "invalid")
        unusual: np.ndarray (bool)
    """
    n = len(chunk_df)
    X = chunk_df[features].copy()

    for col in features:
        X[col] = pd.to_numeric(X[col], errors="coerce")
    X.replace([np.inf, -np.inf], np.nan, inplace=True)

    unusable_counts = X.isna().sum(axis=1).to_numpy()
    invalid_mask = (unusable_counts / len(features)) > 0.20

    scores = np.full(n, np.nan, dtype=np.float64)
    labels = np.array(["invalid"] * n, dtype=object)
    unusual = np.zeros(n, dtype=bool)

    valid_indices = np.where(~invalid_mask)[0]
    if len(valid_indices) > 0:
        X_valid = X.iloc[valid_indices]

        # 1. Supervised scoring
        probs = model.predict_proba(X_valid)[:, 1]
        scores[valid_indices] = probs
        labels[valid_indices] = np.where(probs >= threshold, "suspicious", "benign")

        # 2. Novelty scoring (Isolation Forest)
        # Never merge unusual into suspicious!
        X_filled = X_valid.fillna(novelty_medians)
        nov_scores = -novelty_model.score_samples(X_filled)
        unusual[valid_indices] = nov_scores > novelty_threshold

    return invalid_mask, scores, labels, unusual


class FlowService:
    async def validate_header(self, file: UploadFile, model_service: ModelService) -> tuple[list[str], list[str]]:
        """
        Reads only the CSV header first.
        Returns (normalized_columns, warnings).
        Raises HTTPException(422) if required model features are missing.
        """
        header_bytes = await file.read(65536)
        if not header_bytes:
            raise HTTPException(
                status_code=422,
                detail="Uploaded file is empty",
            )

        newline_pos = header_bytes.find(b"\n")
        if newline_pos == -1:
            header_line = header_bytes.decode("utf-8", errors="replace")
        else:
            header_line = header_bytes[:newline_pos].decode("utf-8", errors="replace")

        # Rewind file to start for streaming
        await file.seek(0)

        reader = csv.reader(io.StringIO(header_line))
        try:
            raw_cols = next(reader)
        except StopIteration:
            raise HTTPException(
                status_code=422,
                detail="Could not read CSV header",
            )

        normalized_cols = [c.strip().lower() for c in raw_cols]
        available_cols = set(normalized_cols)

        # Check required model features
        missing_features = [f for f in model_service.features if f not in available_cols]
        if missing_features:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "Uploaded CSV is missing required model features",
                    "missing_features": sorted(missing_features),
                    "missing_count": len(missing_features),
                },
            )


        # Collect metadata warnings
        warnings = []
        if not _find_column(["src_ip", "source_ip", "src ip", "source ip", "srcip"], available_cols):
            warnings.append("Missing 'src_ip' column; flows lacking source IP will not participate in correlation.")
        if not _find_column(["ts", "timestamp", "time", "date_time", "datetime"], available_cols):
            warnings.append("Missing 'ts' (timestamp) column; flows lacking timestamps will not participate in correlation.")
        if not _find_column(["dst_ip", "destination_ip", "dst ip", "destination ip", "dstip"], available_cols):
            warnings.append("Missing 'dst_ip' column.")
        if not _find_column(["dst_port", "destination_port", "destination port", "dst port", "dstport"], available_cols):
            warnings.append("Missing 'dst_port' column.")

        return normalized_cols, warnings

    async def stream_to_temp_file(self, file: UploadFile) -> str:
        """
        Enforce upload size limit while streaming to a temporary file.
        Cleans up partial temp file if size limit is exceeded or error occurs.
        """
        max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        total_bytes = 0

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
        temp_path = temp_file.name
        try:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB",
                    )
                temp_file.write(chunk)
            temp_file.flush()
            temp_file.close()
            return temp_path
        except Exception:
            temp_file.close()
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise


    async def process_upload(
        self,
        file: UploadFile,
        model_service: ModelService,
        upload_id: str | None = None,
    ) -> UploadResponse:
        upload_id = upload_id or str(uuid.uuid4())
        normalized_cols, warnings = await self.validate_header(file, model_service)

        temp_path = await self.stream_to_temp_file(file)
        try:
            available_cols = set(normalized_cols)
            src_ip_col = _find_column(["src_ip", "source_ip", "src ip", "source ip", "srcip"], available_cols)
            dst_ip_col = _find_column(["dst_ip", "destination_ip", "dst ip", "destination ip", "dstip"], available_cols)
            dst_port_col = _find_column(["dst_port", "destination_port", "destination port", "dst port", "dstport"], available_cols)
            ts_col = _find_column(["ts", "timestamp", "time", "date_time", "datetime"], available_cols)

            total_rows = 0
            valid_rows = 0
            invalid_rows = 0
            suspicious_rows = 0
            unusual_rows = 0

            current_flow_id = 0
            current_row_index = 0

            flows_coll = mongodb.get_collection("flows")
            db_batch: list[dict[str, Any]] = []

            # Stream CSV in chunks
            for chunk_df in pd.read_csv(temp_path, chunksize=settings.CHUNK_SIZE_ROWS):
                chunk_df.columns = [c.strip().lower() for c in chunk_df.columns]
                chunk_len = len(chunk_df)

                # CPU-bound scoring run in threadpool
                invalid_mask, scores, labels, unusual = await asyncio.to_thread(
                    score_chunk_sync,
                    chunk_df,
                    model_service.features,
                    model_service.model,
                    model_service.threshold,
                    model_service.novelty_model,
                    model_service.novelty_medians,
                    model_service.novelty_threshold,
                )

                # Build flow documents
                for idx in range(chunk_len):
                    current_flow_id += 1
                    current_row_index += 1

                    score_val = scores[idx]
                    score = float(score_val) if pd.notna(score_val) else None
                    lbl = str(labels[idx])
                    is_unusual = bool(unusual[idx])

                    src_ip = None
                    if src_ip_col and pd.notna(chunk_df.iat[idx, chunk_df.columns.get_loc(src_ip_col)]):
                        src_ip = str(chunk_df.iat[idx, chunk_df.columns.get_loc(src_ip_col)]).strip()

                    dst_ip = None
                    if dst_ip_col and pd.notna(chunk_df.iat[idx, chunk_df.columns.get_loc(dst_ip_col)]):
                        dst_ip = str(chunk_df.iat[idx, chunk_df.columns.get_loc(dst_ip_col)]).strip()

                    dst_port = None
                    if dst_port_col and pd.notna(chunk_df.iat[idx, chunk_df.columns.get_loc(dst_port_col)]):
                        try:
                            dst_port = int(float(chunk_df.iat[idx, chunk_df.columns.get_loc(dst_port_col)]))
                        except (ValueError, TypeError):
                            dst_port = None

                    ts = None
                    if ts_col and pd.notna(chunk_df.iat[idx, chunk_df.columns.get_loc(ts_col)]):
                        ts = str(chunk_df.iat[idx, chunk_df.columns.get_loc(ts_col)]).strip()

                    flow_doc = {
                        "flow_id": current_flow_id,
                        "upload_id": upload_id,
                        "row_index": current_row_index,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "ts": ts,
                        "score": score,
                        "label": lbl,
                        "unusual": is_unusual,
                        "incident_id": None,
                    }
                    db_batch.append(flow_doc)

                    if len(db_batch) >= settings.DB_BATCH_SIZE:
                        if mongodb.is_connected:
                            await flows_coll.insert_many(db_batch, ordered=False)
                        db_batch = []

                total_rows += chunk_len
                inv_count = int(invalid_mask.sum())
                invalid_rows += inv_count
                valid_rows += (chunk_len - inv_count)
                suspicious_rows += int((labels == "suspicious").sum())
                unusual_rows += int(unusual.sum())

            # Flush remaining batch
            if db_batch and mongodb.is_connected:
                await flows_coll.insert_many(db_batch, ordered=False)

            # Store upload summary document
            if mongodb.is_connected:
                uploads_coll = mongodb.get_collection("uploads")
                await uploads_coll.insert_one(
                    {
                        "upload_id": upload_id,
                        "filename": file.filename,
                        "total_rows": total_rows,
                        "valid_rows": valid_rows,
                        "invalid_rows": invalid_rows,
                        "suspicious_rows": suspicious_rows,
                        "unusual_rows": unusual_rows,
                        "warnings": warnings,
                    }
                )

            # Persist uploaded CSV to configured UPLOAD_DIR
            upload_dir = Path(settings.UPLOAD_DIR)
            upload_dir.mkdir(parents=True, exist_ok=True)
            permanent_csv_path = upload_dir / f"{upload_id}.csv"
            try:
                shutil.copyfile(temp_path, permanent_csv_path)
            except Exception as exc:
                logger.warning("Could not persist uploaded CSV to %s: %s", permanent_csv_path, exc)

            # Trigger flow correlation if MongoDB is connected
            incident_count = 0
            if mongodb.is_connected:
                from services.correlation_service import correlation_service

                incidents, warnings = await correlation_service.correlate_upload(upload_id, warnings)
                incident_count = len(incidents)

            return UploadResponse(
                upload_id=upload_id,
                total_rows=total_rows,
                valid_rows=valid_rows,
                invalid_rows=invalid_rows,
                suspicious_rows=suspicious_rows,
                unusual_rows=unusual_rows,
                warnings=warnings,
                incident_count=incident_count,
            )
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError as exc:
                    logger.warning("Could not delete temporary file %s: %s", temp_path, exc)



flow_service = FlowService()
