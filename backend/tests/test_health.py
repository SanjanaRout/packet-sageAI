from fastapi.testclient import TestClient
from app import app


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/api/v1/health/")
        assert response.status_code == 200
        data = response.json()
        assert "model" in data
        assert data["model"]["model_loaded"] is True
        assert data["model"]["status"] == "loaded"
        assert data["model"]["features_count"] == 78
        assert data["model"]["sklearn_version"] == "1.6.1"


def test_health_endpoint_model_unloaded(monkeypatch):
    from services.model_service import model_service
    monkeypatch.setattr(model_service, "load", lambda *args, **kwargs: None)
    monkeypatch.setattr(model_service, "is_loaded", False)
    with TestClient(app) as client:
        response = client.get("/api/v1/health/")
        assert response.status_code == 200
        data = response.json()
        assert data["model"]["model_loaded"] is False
        assert data["model"]["status"] == "unloaded"


