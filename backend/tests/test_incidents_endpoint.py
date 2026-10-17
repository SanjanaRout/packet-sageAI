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


def test_get_isolated_flows_endpoint(monkeypatch):
    async def mock_get_isolated(upload_id):
        return {
            "upload_id": upload_id,
            "flow_ids": [10, 20, 30],
            "total_count": 3,
        }

    monkeypatch.setattr(correlation_service, "get_isolated_flows", mock_get_isolated)

    with TestClient(app) as client:
        # Test /isolated
        res = client.get("/api/v1/incidents/isolated?upload_id=up-789")
        assert res.status_code == 200
        data = res.json()
        assert data["upload_id"] == "up-789"
        assert data["flow_ids"] == [10, 20, 30]
        assert data["total_count"] == 3

        # Test /isolated-flows
        res2 = client.get("/api/v1/incidents/isolated-flows?upload_id=up-789")
        assert res2.status_code == 200
        assert res2.json()["total_count"] == 3


def test_list_incidents_with_include_isolated(monkeypatch):
    async def mock_get_incidents(upload_id=None):
        return []

    async def mock_get_isolated(upload_id):
        return {
            "upload_id": upload_id,
            "flow_ids": [1, 2],
            "total_count": 2,
        }

    monkeypatch.setattr(correlation_service, "get_incidents", mock_get_incidents)
    monkeypatch.setattr(correlation_service, "get_isolated_flows", mock_get_isolated)

    with TestClient(app) as client:
        res = client.get("/api/v1/incidents/?upload_id=up-100&include_isolated=true")
        assert res.status_code == 200
        data = res.json()
        assert "incidents" in data
        assert "isolated_flagged_flows" in data
        assert data["isolated_flagged_flows"]["total_count"] == 2
        assert res.headers.get("X-Isolated-Flow-Count") == "2"

