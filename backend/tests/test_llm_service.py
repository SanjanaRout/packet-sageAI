from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app import app
from core.config import settings
from services.assistant_service import AssistantService, extract_citations
from services.correlation_service import correlation_service
from services.llm.anthropic_provider import AnthropicProvider
from services.llm.base import (
    LLMAuthError,
    LLMConfigError,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
)
from services.llm.factory import get_llm_provider
from services.llm.openai_compat import OpenAICompatProvider


def test_factory_provider_selection(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai_compat")
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    provider = get_llm_provider(refresh=True)
    assert isinstance(provider, OpenAICompatProvider)

    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    provider = get_llm_provider(refresh=True)
    assert isinstance(provider, AnthropicProvider)


def test_config_validation_empty_key():
    # Empty key with remote URL raises LLMConfigError
    with pytest.raises(LLMConfigError):
        OpenAICompatProvider(api_key="", model="gpt-4o", base_url="https://api.openai.com/v1")

    # Empty key with localhost is allowed
    local_provider = OpenAICompatProvider(api_key="", model="llama3", base_url="http://localhost:11434/v1")
    assert local_provider.model == "llama3"

    # Anthropic requires key unconditionally
    with pytest.raises(LLMConfigError):
        AnthropicProvider(api_key="", model="claude-3-5-sonnet")


def test_system_as_user_formatting():
    prov_normal = OpenAICompatProvider(api_key="k", model="m", base_url="http://localhost:11434/v1", system_as_user=False)
    msgs_normal = prov_normal._build_messages("sys", "usr")
    assert len(msgs_normal) == 2
    assert msgs_normal[0]["role"] == "system"

    prov_user = OpenAICompatProvider(api_key="k", model="m", base_url="http://localhost:11434/v1", system_as_user=True)
    msgs_user = prov_user._build_messages("sys", "usr")
    assert len(msgs_user) == 1
    assert msgs_user[0]["role"] == "user"
    assert "sys" in msgs_user[0]["content"]
    assert "usr" in msgs_user[0]["content"]


@pytest.mark.anyio
async def test_openai_compat_max_tokens_fallback():
    prov = OpenAICompatProvider(api_key="k", model="m", base_url="http://localhost:11434/v1")

    import openai
    bad_req = openai.BadRequestError("Unsupported parameter: max_tokens. Use max_completion_tokens.", response=MagicMock(status_code=400), body={})

    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock(message=MagicMock(content="fallback success"))]

    mock_create = AsyncMock(side_effect=[bad_req, mock_resp])
    prov.client.chat.completions.create = mock_create

    result = await prov.complete("sys", "usr", max_tokens=100, temperature=0.2)
    assert result == "fallback success"
    assert mock_create.call_count == 2
    # Verify second call used max_completion_tokens
    assert "max_completion_tokens" in mock_create.call_args_list[1].kwargs


@pytest.mark.anyio
async def test_retry_on_rate_limit_and_timeout():
    prov = OpenAICompatProvider(api_key="k", model="m", base_url="http://localhost:11434/v1", max_retries=1)

    import openai
    rate_err = openai.RateLimitError("Rate limit", response=MagicMock(status_code=429), body={})
    mock_resp = MagicMock()
    mock_resp.choices = [MagicMock(message=MagicMock(content="retry ok"))]

    prov.client.chat.completions.create = AsyncMock(side_effect=[rate_err, mock_resp])
    with patch("asyncio.sleep", AsyncMock()):
        result = await prov.complete("sys", "usr", max_tokens=50, temperature=0.1)
    assert result == "retry ok"


@pytest.mark.anyio
async def test_no_retry_on_auth_error():
    prov = OpenAICompatProvider(api_key="k", model="m", base_url="http://localhost:11434/v1", max_retries=2)

    import openai
    auth_err = openai.AuthenticationError("Invalid API key", response=MagicMock(status_code=401), body={})
    prov.client.chat.completions.create = AsyncMock(side_effect=auth_err)

    with pytest.raises(LLMAuthError):
        await prov.complete("sys", "usr", max_tokens=50, temperature=0.1)
    assert prov.client.chat.completions.create.call_count == 1


def test_extract_citations():
    text = "Traffic observed in [flow 12] and [flow 15] indicates anomalous behavior, unlike [flow 99]."
    valid_ids = {12, 15}
    valid, invalid = extract_citations(text, valid_ids)
    assert valid == [12, 15]
    assert invalid == [99]


@pytest.mark.anyio
async def test_build_prompt_contains_evidence_and_boundary(monkeypatch):
    from core.database import mongodb

    class FakeFlowCursor:
        def sort(self, *args, **kwargs):
            return self
        def limit(self, *args, **kwargs):
            return self
        async def to_list(self, length=None):
            return [
                {"flow_id": 1, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 80, "ts": "2026-10-15 10:00:00", "score": 0.88, "label": "suspicious", "unusual": False},
                {"flow_id": 2, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 80, "ts": "2026-10-15 10:00:01", "score": 0.92, "label": "suspicious", "unusual": True},
            ]

    class FakeColl:
        def find(self, *args, **kwargs):
            return FakeFlowCursor()

    monkeypatch.setattr(mongodb, "get_collection", lambda name: FakeColl())

    svc = AssistantService()
    incident = {
        "incident_id": "inc-test",
        "upload_id": "up-1",
        "kinds": ["suspicious_burst"],
        "reasons": ["2 flagged flows"],
        "start": "2026-10-15 10:00:00",
        "end": "2026-10-15 10:00:01",
        "flow_count": 2,
        "max_score": 0.92,
        "flow_ids": [1, 2],
        "feedback": [{"decision": "inconclusive", "note": "Needs PCAP inspection", "timestamp": "2026-10-15T10:05:00Z"}],
    }

    prompt, flow_ids = await svc.build_prompt(incident, "Is this a known scan?")
    assert "<evidence>" in prompt
    assert "</evidence>" in prompt
    assert "<analyst_feedback>" in prompt
    assert "[flow 1]" in prompt
    assert "[flow 2]" in prompt
    assert "Is this a known scan?" in prompt
    assert flow_ids == {1, 2}


def test_llm_status_endpoint():
    with TestClient(app) as client:
        resp = client.get("/api/v1/llm/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "provider" in data
        assert "model" in data
        assert "configured" in data
        assert "base_url_host" in data
        # Ensure API key is NEVER exposed in status
        assert "api_key" not in data
        assert "key" not in data


def test_ask_incident_endpoint_status_codes(monkeypatch):
    from services.assistant_service import assistant_service

    mock_incident = {
        "incident_id": "inc-100",
        "upload_id": "up-1",
        "flow_ids": [1],
    }
    monkeypatch.setattr(correlation_service, "get_incident_detail", AsyncMock(return_value=mock_incident))

    # Test 503 for LLMConfigError
    monkeypatch.setattr(assistant_service, "ask_incident", AsyncMock(side_effect=LLMConfigError("missing key")))
    with TestClient(app) as client:
        res = client.post("/api/v1/incidents/inc-100/ask", json={})
        assert res.status_code == 503

    # Test 502 for LLMAuthError
    monkeypatch.setattr(assistant_service, "ask_incident", AsyncMock(side_effect=LLMAuthError("bad key")))
    with TestClient(app) as client:
        res = client.post("/api/v1/incidents/inc-100/ask", json={})
        assert res.status_code == 502

    # Test 429 for LLMRateLimitError
    monkeypatch.setattr(assistant_service, "ask_incident", AsyncMock(side_effect=LLMRateLimitError("rate limited")))
    with TestClient(app) as client:
        res = client.post("/api/v1/incidents/inc-100/ask", json={})
        assert res.status_code == 429

    # Test 504 for LLMTimeoutError
    monkeypatch.setattr(assistant_service, "ask_incident", AsyncMock(side_effect=LLMTimeoutError("timeout")))
    with TestClient(app) as client:
        res = client.post("/api/v1/incidents/inc-100/ask", json={})
        assert res.status_code == 504


def test_feedback_endpoint_valid_and_invalid(monkeypatch):
    mock_feedback_result = {
        "incident_id": "inc-555",
        "decision": "confirmed",
        "note": "Corroborated by host firewall alert",
        "timestamp": "2026-10-15T12:00:00Z",
        "feedback_count": 1,
    }
    monkeypatch.setattr(correlation_service, "add_feedback", AsyncMock(return_value=mock_feedback_result))

    with TestClient(app) as client:
        # Valid decision
        resp = client.post(
            "/api/v1/incidents/inc-555/feedback",
            json={"decision": "confirmed", "note": "Corroborated by host firewall alert"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["decision"] == "confirmed"
        assert data["feedback_count"] == 1

        # Invalid decision returns 422
        resp_invalid = client.post(
            "/api/v1/incidents/inc-555/feedback",
            json={"decision": "malicious", "note": "Invalid decision string"},
        )
        assert resp_invalid.status_code == 422


@pytest.mark.skipif(not os.getenv("LLM_LIVE_TEST"), reason="Opt-in live test disabled unless LLM_LIVE_TEST=1 is set")
@pytest.mark.anyio
async def test_llm_live_completion():
    prov = get_llm_provider(refresh=True)
    res = await prov.complete(
        system="Reply with exactly 'OK'",
        user="Test message",
        max_tokens=10,
        temperature=0.0,
    )
    assert len(res) > 0
