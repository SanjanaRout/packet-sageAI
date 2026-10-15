import io
import pytest
from fastapi.testclient import TestClient

from app import app
from services.model_service import model_service


@pytest.fixture(autouse=True)
def ensure_model_loaded():
    if not model_service.is_loaded:
        model_service.load()


def test_upload_non_csv_rejected():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/flows/upload",
            files={"file": ("test.txt", b"hello world", "text/plain")},
        )
        assert response.status_code == 400
        assert "must be a CSV" in response.json()["detail"]


def test_upload_missing_features_returns_422():
    csv_data = "src_ip,dst_ip,dst_port\n1.1.1.1,2.2.2.2,80\n"
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/flows/upload",
            files={"file": ("test.csv", csv_data.encode("utf-8"), "text/csv")},
        )
        assert response.status_code == 422
        data = response.json()["detail"]
        assert "missing_features" in data
        assert len(data["missing_features"]) > 0


def test_upload_valid_csv_scoring():
    # Construct a valid CSV with all 78 features + metadata columns
    features = list(model_service.features)
    headers = ["src_ip", "dst_ip", "dst_port", "ts"] + features
    # Row 1: valid numbers
    row1 = ["192.168.1.10", "10.0.0.1", "443", "2026-10-15 10:00:00"] + ["0"] * len(features)
    # Row 2: >20% invalid features (empty strings)
    row2 = ["192.168.1.11", "10.0.0.1", "443", "2026-10-15 10:00:01"] + [""] * 25 + ["0"] * (len(features) - 25)

    csv_content = "\n".join([",".join(headers), ",".join(row1), ",".join(row2)])

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/flows/upload",
            files={"file": ("network_flows.csv", csv_content.encode("utf-8"), "text/csv")},
        )
        assert response.status_code == 201
        data = response.json()
        assert "upload_id" in data
        assert data["total_rows"] == 2
        assert data["valid_rows"] == 1
        assert data["invalid_rows"] == 1
        assert isinstance(data["suspicious_rows"], int)
        assert isinstance(data["unusual_rows"], int)
        assert isinstance(data["warnings"], list)
