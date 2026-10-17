from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import uuid
from typing import Any

import pandas as pd

from core.config import settings
from core.database import mongodb
from services.correlation_engine import correlate_flows

logger = logging.getLogger("packet_sage")

CANDIDATE_TIMESTAMP_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
]


class CorrelationService:
    async def correlate_upload(
        self,
        upload_id: str,
        initial_warnings: list[str] | None = None,
        assume_pm_business_hours: bool | None = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        warnings = list(initial_warnings or [])

        flows_coll = mongodb.get_collection("flows")
        # Load only needed fields from Mongo using projection
        cursor = flows_coll.find(
            {"upload_id": upload_id},
            projection={
                "_id": 0,
                "flow_id": 1,
                "src_ip": 1,
                "dst_ip": 1,
                "dst_port": 1,
                "ts": 1,
                "score": 1,
                "label": 1,
            },
        )
        flow_docs = await cursor.to_list(length=None)

        if not flow_docs:
            return [], warnings

        df = pd.DataFrame(flow_docs)
        if "flow_id" in df.columns:
            df["id"] = df["flow_id"]

        # Check for IP and timestamp presence
        has_src_ip = "src_ip" in df.columns and df["src_ip"].notna().any()
        has_ts = "ts" in df.columns and df["ts"].notna().any()

        if not has_src_ip or not has_ts:
            warnings.append("Upload lacks IP or timestamp metadata; correlation skipped.")
            return [], warnings

        # Skip and count flows with missing src_ip
        missing_src_count = int(df["src_ip"].isna().sum())
        if missing_src_count > 0:
            warnings.append(
                f"{missing_src_count} flows were missing source IP and were excluded from correlation."
            )

        # Parse timestamps: try ordered candidate formats and pick the one that parses the most rows
        raw_ts = df["ts"].dropna()
        best_format = None
        best_parsed = None
        max_valid_count = 0

        for fmt in CANDIDATE_TIMESTAMP_FORMATS:
            parsed_candidate = pd.to_datetime(raw_ts, format=fmt, errors="coerce")
            valid_count = int(parsed_candidate.notna().sum())
            if valid_count > max_valid_count:
                max_valid_count = valid_count
                best_format = fmt
                best_parsed = parsed_candidate

        if best_format is None or max_valid_count == 0:
            warnings.append(
                "Could not parse any timestamps using supported candidate formats; correlation skipped."
            )
            return [], warnings

        df["parsed_ts"] = pd.to_datetime(df["ts"], format=best_format, errors="coerce")
        unparseable_count = int(raw_ts.notna().sum() - max_valid_count)
        warnings.append(
            f"Parsed timestamps using format '{best_format}' "
            f"({unparseable_count} unparseable row(s) excluded from correlation)."
        )

        should_shift_hours = (
            assume_pm_business_hours
            if assume_pm_business_hours is not None
            else settings.ASSUME_NO_AMPM_BUSINESS_HOURS
        )

        time_shift_applied = False
        if should_shift_hours:
            hours = df["parsed_ts"].dt.hour
            shift_mask = hours.between(settings.AMPM_PM_HOURS_START, settings.AMPM_PM_HOURS_END, inclusive="both")
            shifted_count = int(shift_mask.sum())
            if shifted_count > 0:
                df.loc[shift_mask, "parsed_ts"] += pd.Timedelta(hours=12)
                time_shift_applied = True
                warnings.append(
                    f"Assumed 12-hour PM clock for business hours {settings.AMPM_PM_HOURS_START}..{settings.AMPM_PM_HOURS_END}; "
                    f"shifted {shifted_count} row(s) forward by 12 hours."
                )

        valid_parsed = df["parsed_ts"].dropna()
        if not valid_parsed.empty:
            # Per-upload hour-of-day histogram to logs
            hour_hist = valid_parsed.dt.hour.value_counts().sort_index().to_dict()
            logger.info("Upload %s hour-of-day histogram: %s", upload_id, hour_hist)

            min_ts = valid_parsed.min()
            max_ts = valid_parsed.max()
            if min_ts < pd.Timestamp("2017-07-03") or max_ts > pd.Timestamp("2017-07-07 23:59:59"):
                warnings.append(
                    f"Warning: Parsed dates [{min_ts} to {max_ts}] fall outside expected range 2017-07-03..2017-07-07."
                )
        df["ts"] = df["parsed_ts"]

        # Filter valid flows for correlation
        valid_df = df.dropna(subset=["ts", "src_ip"]).copy()
        if valid_df.empty:
            warnings.append("No valid flows remained after filtering missing IPs/timestamps; 0 incidents formed.")
            return [], warnings

        # Ensure required correlation columns exist
        for col in ["dst_ip", "dst_port", "score", "label"]:
            if col not in valid_df.columns:
                valid_df[col] = None

        # Run CPU-bound correlation in threadpool
        raw_incidents, isolated_flow_ids = await asyncio.to_thread(
            correlate_flows,
            valid_df,
            scan_ports=settings.SCAN_MIN_PORTS,
            scan_max_dst_port=settings.SCAN_MAX_DST_PORT,
            min_burst_flows=settings.MIN_BURST_FLOWS,
            isolated_flow_max=settings.ISOLATED_FLOW_MAX,
            return_isolated=True,
        )

        persisted_incidents: list[dict[str, Any]] = []
        incidents_coll = mongodb.get_collection("incidents")

        if mongodb.is_connected:
            # Idempotency: replace existing incidents for this upload instead of duplicating
            await incidents_coll.delete_many({"upload_id": upload_id})
            await flows_coll.update_many(
                {"upload_id": upload_id},
                {"$set": {"incident_id": None}},
            )

            # Record isolated flows and time_shift_applied on upload document
            uploads_coll = mongodb.get_collection("uploads")
            await uploads_coll.update_one(
                {"upload_id": upload_id},
                {
                    "$set": {
                        "isolated_flagged_flows": {
                            "flow_ids": isolated_flow_ids[:1000],
                            "total_count": len(isolated_flow_ids),
                        },
                        "time_shift_applied": time_shift_applied,
                    }
                },
            )


            # Persist parsed datetime objects into Mongo for valid flows
            # Convert timestamp series to native Python datetimes
            updates = []
            for _, row in valid_df.iterrows():
                ts_val = row["ts"]
                if pd.notna(ts_val):
                    py_dt = ts_val.to_pydatetime()
                    updates.append((row["id"], py_dt))

            # Batch update timestamp in Mongo if needed
            for fid, py_dt in updates[:2000]:  # batch update first chunk
                await flows_coll.update_one(
                    {"upload_id": upload_id, "flow_id": fid},
                    {"$set": {"ts_dt": py_dt}},
                )

        for inc in raw_incidents:
            incident_id = f"inc-{uuid.uuid4().hex[:12]}"
            now_iso = datetime.now(timezone.utc).isoformat()

            inc_doc = {
                "incident_id": incident_id,
                "upload_id": upload_id,
                "kinds": inc["kinds"],
                "start": str(inc["start"]),
                "end": str(inc["end"]),
                "flow_count": int(inc["flow_count"]),
                "max_score": float(inc["max_score"]),
                "src_ips": list(inc["src_ips"])[:10],
                "dst_ips": list(inc["dst_ips"])[:10],
                "reasons": list(inc["reasons"]),
                "flow_ids": [int(fid) for fid in inc["flow_ids"]],
                "status": "open",
                "time_shift_applied": time_shift_applied,
                "created_at": now_iso,
            }

            if mongodb.is_connected:
                await incidents_coll.insert_one(inc_doc)
                await flows_coll.update_many(
                    {"upload_id": upload_id, "flow_id": {"$in": inc_doc["flow_ids"]}},
                    {"$set": {"incident_id": incident_id}},
                )

            persisted_incidents.append(inc_doc)

        logger.info(
            "Correlation complete for upload %s: %d incident(s) formed from %d flows",
            upload_id,
            len(persisted_incidents),
            len(valid_df),
        )
        return persisted_incidents, warnings

    async def get_incidents(self, upload_id: str | None = None) -> list[dict[str, Any]]:
        incidents_coll = mongodb.get_collection("incidents")
        query = {"upload_id": upload_id} if upload_id else {}
        cursor = incidents_coll.find(query, projection={"_id": 0}).sort("max_score", -1)
        incidents = await cursor.to_list(length=None)
        return incidents

    async def get_isolated_flows(self, upload_id: str) -> dict[str, Any]:
        uploads_coll = mongodb.get_collection("uploads")
        doc = await uploads_coll.find_one({"upload_id": upload_id}, projection={"_id": 0, "isolated_flagged_flows": 1})
        if not doc or "isolated_flagged_flows" not in doc:
            return {"upload_id": upload_id, "flow_ids": [], "total_count": 0}
        data = doc["isolated_flagged_flows"]
        return {
            "upload_id": upload_id,
            "flow_ids": data.get("flow_ids", []),
            "total_count": data.get("total_count", 0),
        }

    async def get_incident_detail(
        self,
        incident_id: str,
        skip: int = 0,
        limit: int = 200,
    ) -> dict[str, Any] | None:
        incidents_coll = mongodb.get_collection("incidents")
        incident = await incidents_coll.find_one({"incident_id": incident_id}, projection={"_id": 0})
        if not incident:
            return None

        total_flows = incident.get("flow_count", len(incident.get("flow_ids", [])))

        flows_coll = mongodb.get_collection("flows")
        flow_cursor = (
            flows_coll.find(
                {"upload_id": incident["upload_id"], "flow_id": {"$in": incident["flow_ids"]}},
                projection={"_id": 0},
            )
            .sort("flow_id", 1)
            .skip(skip)
            .limit(limit)
        )
        flows = await flow_cursor.to_list(length=None)

        incident["flows"] = flows
        incident["total_flows"] = total_flows
        incident["skip"] = skip
        incident["limit"] = limit
        incident["feedback"] = incident.get("feedback", [])
        return incident

    async def add_feedback(
        self,
        incident_id: str,
        decision: str,
        note: str,
    ) -> dict[str, Any] | None:
        incidents_coll = mongodb.get_collection("incidents")
        incident = await incidents_coll.find_one({"incident_id": incident_id})
        if not incident:
            return None

        now_iso = datetime.now(timezone.utc).isoformat()
        feedback_entry = {
            "decision": decision,
            "note": note,
            "timestamp": now_iso,
        }

        # Append-only history; update latest_decision field
        await incidents_coll.update_one(
            {"incident_id": incident_id},
            {
                "$push": {"feedback": feedback_entry},
                "$set": {"latest_decision": decision},
            },
        )
        updated = await incidents_coll.find_one({"incident_id": incident_id})
        count = len(updated.get("feedback", []))
        return {
            "incident_id": incident_id,
            "decision": decision,
            "note": note,
            "timestamp": now_iso,
            "feedback_count": count,
        }


correlation_service = CorrelationService()

