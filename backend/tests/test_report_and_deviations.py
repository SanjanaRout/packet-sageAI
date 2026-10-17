import pytest
from fastapi.testclient import TestClient

from app import app
from services.baseline_service import BaselineService, DISCLAIMER_TEXT, baseline_service
from services.assistant_service import assistant_service
from services.report_service import report_service
from services.correlation_service import correlation_service
from core.database import mongodb


def test_baseline_service_extremity_and_disclaimer():
    service = BaselineService()
    assert service.stats is not None
    assert len(service.stats) > 0

    # Destination port p50 is 80.0, p95 is ~443/8080, p99 is ~5353/8080
    # Let's craft features with extreme values
    extreme_features = {
        "Destination Port": 60000.0,
        "Total Fwd Packets": 5000.0,
        "Flow Duration": 1.0,
    }

    deviations = service.compute_flow_deviations(extreme_features, top_k=3)
    assert len(deviations) > 0
    for dev in deviations:
        assert "feature" in dev
        assert "value" in dev
        assert "benign_median" in dev
        assert "bracket" in dev
        assert "disclaimer" in dev
        assert dev["disclaimer"] == DISCLAIMER_TEXT
        assert dev["is_extreme"] is True

    # Test formatted text helper
    text = service.format_deviations_text(deviations)
    assert DISCLAIMER_TEXT in text
    assert "benign median:" in text


@pytest.mark.anyio
async def test_assistant_service_build_prompt_deviations(monkeypatch):
    incident = {
        "incident_id": "inc-dev-1",
        "upload_id": "up-dev-1",
        "kinds": ["port_scan"],
        "flow_ids": [101, 102],
        "flow_count": 2,
        "start": "2017-07-07 09:30:00",
        "end": "2017-07-07 09:31:00",
        "feedback": [
            {"decision": "confirmed_threat", "note": "Port scanning activity verified", "timestamp": "2026-10-17T12:00:00Z"}
        ],
    }

    mock_flows = [
        {
            "upload_id": "up-dev-1",
            "flow_id": 101,
            "ts": "2017-07-07 09:30:00",
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "dst_port": 21,
            "score": 0.95,
            "label": "anomaly",
            "unusual": True,
            "deviations": [
                {
                    "feature": "Destination Port",
                    "value": 21.0,
                    "benign_median": 80.0,
                    "bracket": "<25th percentile of benign training traffic",
                    "disclaimer": DISCLAIMER_TEXT,
                }
            ],
        },
        {
            "upload_id": "up-dev-1",
            "flow_id": 102,
            "ts": "2017-07-07 09:30:01",
            "src_ip": "172.16.0.1",
            "dst_ip": "192.168.10.50",
            "dst_port": 22,
            "score": 0.91,
            "label": "anomaly",
            "unusual": True,
            "features": {"Destination Port": 49152.0},
        },
    ]

    class MockCursor:
        def __init__(self, items):
            self.items = items

        def sort(self, *args, **kwargs):
            return self

        def limit(self, *args, **kwargs):
            return self

        async def to_list(self, length=None):
            return self.items

    class MockCollection:
        def find(self, *args, **kwargs):
            return MockCursor(mock_flows)

    monkeypatch.setattr(mongodb, "get_collection", lambda coll: MockCollection())

    prompt, valid_ids = await assistant_service.build_prompt(incident, user_question="Why was this flagged?")
    assert 101 in valid_ids
    assert 102 in valid_ids
    assert "<evidence>" in prompt
    assert "[flow 101]" in prompt
    assert "Deviations vs. Benign Baseline:" in prompt
    assert DISCLAIMER_TEXT in prompt
    assert "Destination Port" in prompt


@pytest.mark.anyio
async def test_report_service_deterministic_generation(monkeypatch):
    mock_incident_detail = {
        "incident_id": "inc-rpt-123",
        "upload_id": "up-rpt-456",
        "kinds": ["port_scan", "suspicious_burst"],
        "start": "2017-07-07 14:30:00",
        "end": "2017-07-07 14:31:00",
        "flow_count": 2,
        "max_score": 0.88,
        "src_ips": ["172.16.0.1"],
        "dst_ips": ["192.168.10.50"],
        "reasons": ["172.16.0.1 targeted 2 distinct ports in 60s"],
        "time_shift_applied": True,
        "status": "open",
        "latest_decision": None,
        "feedback": [
            {"decision": "investigating", "note": "Initial review", "timestamp": "2026-10-17T10:00:00Z"}
        ],
        "flows": [
            {
                "flow_id": 1,
                "ts": "2017-07-07 14:30:00",
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "dst_port": 80,
                "score": 0.88,
                "label": "anomaly",
                "unusual": True,
                "deviations": [
                    {
                        "feature": "Destination Port",
                        "value": 80.0,
                        "benign_median": 80.0,
                        "bracket": "within normal benign range (25th-75th percentile)",
                        "z_score": 0.0,
                        "is_extreme": False,
                        "extremity_weight": 0.0,
                        "disclaimer": DISCLAIMER_TEXT,
                    }
                ],
            }
        ],
    }

    async def mock_get_detail(incident_id, skip=0, limit=200):
        if incident_id == "inc-rpt-123":
            return mock_incident_detail
        return None

    monkeypatch.setattr(correlation_service, "get_incident_detail", mock_get_detail)

    report = await report_service.generate_report("inc-rpt-123", generate_llm=False)
    assert report is not None
    assert report.incident_id == "inc-rpt-123"
    assert report.upload_id == "up-rpt-456"

    # Executive summary
    assert "Incident inc-rpt-123 encompasses 2 network flow(s)" in report.executive_summary

    # Observed facts
    assert report.observed_facts.time_shift_applied is True
    assert "12-hour business-hours clock shift WAS applied" in report.observed_facts.time_metadata_note
    assert report.observed_facts.flow_count == 2
    assert "port_scan" in report.observed_facts.rules_triggered
    assert report.observed_facts.score_max == 0.88

    # Hypotheses & Uncertainties
    assert any("Horizontal Port Scan" in h for h in report.hypotheses_and_uncertainties)
    assert any("Benign Alternative" in h for h in report.hypotheses_and_uncertainties)
    assert any("Statistical Evidence Disclaimer" in h for h in report.hypotheses_and_uncertainties)

    # Next steps (human-in-the-loop)
    assert len(report.recommended_next_steps) >= 3
    assert any("Verify whether source IP" in s for s in report.recommended_next_steps)
    assert any("POST /api/v1/incidents/inc-rpt-123/feedback" in s for s in report.recommended_next_steps)

    # Analyst Feedback History
    assert report.analyst_feedback_history.current_status == "open"
    assert len(report.analyst_feedback_history.feedback_entries) == 1
    assert report.analyst_feedback_history.feedback_entries[0].decision == "investigating"


def test_incident_report_endpoints(monkeypatch):
    mock_incident_detail = {
        "incident_id": "inc-rpt-999",
        "upload_id": "up-rpt-999",
        "kinds": ["port_scan"],
        "start": "2017-07-07 14:30:00",
        "end": "2017-07-07 14:31:00",
        "flow_count": 1,
        "max_score": 0.75,
        "src_ips": ["172.16.0.1"],
        "dst_ips": ["192.168.10.50"],
        "reasons": ["172.16.0.1 targeted distinct ports"],
        "time_shift_applied": False,
        "status": "open",
        "latest_decision": None,
        "feedback": [],
        "flows": [
            {
                "flow_id": 99,
                "ts": "2017-07-07 14:30:00",
                "src_ip": "172.16.0.1",
                "dst_ip": "192.168.10.50",
                "dst_port": 443,
                "score": 0.75,
                "label": "anomaly",
                "unusual": False,
                "deviations": [],
            }
        ],
    }

    async def mock_get_detail(incident_id, skip=0, limit=200):
        if incident_id == "inc-rpt-999":
            return mock_incident_detail
        return None

    monkeypatch.setattr(correlation_service, "get_incident_detail", mock_get_detail)

    with TestClient(app) as client:
        # GET report
        res_get = client.get("/api/v1/incidents/inc-rpt-999/report")
        assert res_get.status_code == 200
        data = res_get.json()
        assert data["incident_id"] == "inc-rpt-999"
        assert "executive_summary" in data
        assert "observed_facts" in data
        assert data["observed_facts"]["flow_count"] == 1
        assert "hypotheses_and_uncertainties" in data
        assert "recommended_next_steps" in data
        assert "analyst_feedback_history" in data

        # POST report
        res_post = client.post("/api/v1/incidents/inc-rpt-999/report")
        assert res_post.status_code == 200
        data_post = res_post.json()
        assert data_post["incident_id"] == "inc-rpt-999"

        # 404 on nonexistent incident
        res_404 = client.get("/api/v1/incidents/nonexistent-id/report")
        assert res_404.status_code == 404
