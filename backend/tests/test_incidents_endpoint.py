from fastapi.testclient import TestClient
from app import app
from services.correlation_service import correlation_service


def test_list_incidents_empty(monkeypatch):
    async def mock_get_incidents(upload_id=None):
        return []

    monkeypatch.setattr(correlation_service, "get_incidents", mock_get_incidents)

    with TestClient(app) as client:
        response = client.get("/api/v1/incidents/")
        assert response.status_code == 200
        assert response.json() == []


def test_get_incident_detail_found(monkeypatch):
    async def mock_get_detail(incident_id, skip=0, limit=200):
        if incident_id == "inc-123":
            return {
                "incident_id": "inc-123",
                "upload_id": "up-456",
                "kinds": ["port_scan"],
                "start": "2026-10-15 10:00:00",
                "end": "2026-10-15 10:00:30",
                "flow_count": 25,
                "max_score": 0.85,
                "src_ips": ["192.168.1.100"],
                "dst_ips": ["10.0.0.99"],
                "reasons": ["192.168.1.100 contacted 25 distinct ports in 60s"],
                "flow_ids": list(range(1, 26)),
                "status": "open",
                "created_at": "2026-10-15T10:01:00Z",
                "flows": [],
                "total_flows": 25,
                "skip": skip,
                "limit": limit,
                "feedback": [],
            }
        return None

    monkeypatch.setattr(correlation_service, "get_incident_detail", mock_get_detail)


    with TestClient(app) as client:
        res = client.get("/api/v1/incidents/inc-123")
        assert res.status_code == 200
        data = res.json()
        assert data["incident_id"] == "inc-123"
        assert data["kinds"] == ["port_scan"]
        assert data["status"] == "open"
        assert "feedback" in data

        res404 = client.get("/api/v1/incidents/nonexistent")
        assert res404.status_code == 404
