import io
import pytest
import numpy as np
import pandas as pd
from unittest.mock import MagicMock
from fastapi import HTTPException, UploadFile

from services.model_service import model_service
from services.flow_service import FlowService, score_chunk_sync


@pytest.fixture(autouse=True)
def ensure_model_loaded():
    if not model_service.is_loaded:
        model_service.load()


def test_score_chunk_sync_invalid_rows():
    # Create chunk where row 0 has all NaNs (>20% unusable) and row 1 has valid values
    features = model_service.features
    df = pd.DataFrame(np.zeros((2, len(features))), columns=features)
    # Make row 0 >20% NaNs
    df.iloc[0, :20] = np.nan

    invalid_mask, scores, labels, unusual = score_chunk_sync(
        chunk_df=df,
        features=features,
        model=model_service.model,
        threshold=model_service.threshold,
        novelty_model=model_service.novelty_model,
        novelty_medians=model_service.novelty_medians,
        novelty_threshold=model_service.novelty_threshold,
    )

    assert invalid_mask[0] is True or invalid_mask[0] == 1
    assert labels[0] == "invalid"
    assert np.isnan(scores[0])
    assert unusual[0] == False

    assert invalid_mask[1] is False or invalid_mask[1] == 0
    assert labels[1] in ("benign", "suspicious")
    assert not np.isnan(scores[1])
    assert isinstance(unusual[1], (bool, np.bool_))


def test_score_chunk_sync_threshold_labeling():
    # Verify that label is 'suspicious' if and only if score >= threshold
    features = model_service.features
    mock_model = MagicMock()
    # Mock predict_proba: row 0 prob = 0.5 (above threshold), row 1 prob = 0.05 (below threshold)
    mock_model.predict_proba.return_value = np.array([[0.5, 0.5], [0.95, 0.05]])

    mock_iso = MagicMock()
    mock_iso.score_samples.return_value = np.array([-0.8, -0.1])  # novelty score = -(-0.8)=0.8 (unusual), -(-0.1)=0.1 (not unusual)

    df = pd.DataFrame(np.zeros((2, len(features))), columns=features)
    invalid_mask, scores, labels, unusual = score_chunk_sync(
        chunk_df=df,
        features=features,
        model=mock_model,
        threshold=0.127,
        novelty_model=mock_iso,
        novelty_medians={f: 0.0 for f in features},
        novelty_threshold=0.5,
    )

    assert labels[0] == "suspicious"
    assert scores[0] == 0.5
    assert unusual[0] == True

    assert labels[1] == "benign"
    assert scores[1] == 0.05
    assert unusual[1] == False


@pytest.mark.anyio
async def test_validate_header_missing_features():
    service = FlowService()
    # Missing almost all features
    content = b"src_ip,dst_ip,dst_port\n192.168.1.1,192.168.1.2,80\n"
    upload = UploadFile(filename="test.csv", file=io.BytesIO(content))

    with pytest.raises(HTTPException) as exc_info:
        await service.validate_header(upload, model_service)

    assert exc_info.value.status_code == 422
    assert "missing_features" in exc_info.value.detail
    assert exc_info.value.detail["missing_count"] > 0


@pytest.mark.anyio
async def test_validate_header_success_with_warnings():
    service = FlowService()
    # Create CSV with all 78 required features, but no src_ip or ts
    headers = list(model_service.features)
    content = (",".join(headers) + "\n" + ",".join(["0"] * len(headers)) + "\n").encode("utf-8")
    upload = UploadFile(filename="test.csv", file=io.BytesIO(content))

    cols, warnings = await service.validate_header(upload, model_service)
    assert len(cols) == 78
    assert any("src_ip" in w for w in warnings)
    assert any("ts" in w for w in warnings)


@pytest.mark.anyio
async def test_stream_to_temp_file_size_limit_and_cleanup(monkeypatch):
    import os
    from core.config import settings

    # Set limit very low (e.g., 0.0001 MB ~ 100 bytes)
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_MB", 0.0001)
    service = FlowService()

    large_content = b"x" * 2000
    upload = UploadFile(filename="oversized.csv", file=io.BytesIO(large_content))

    with pytest.raises(HTTPException) as exc_info:
        await service.stream_to_temp_file(upload)

    assert exc_info.value.status_code == 413

