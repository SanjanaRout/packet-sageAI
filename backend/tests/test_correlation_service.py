import time
from datetime import datetime, timedelta
import numpy as np
import pandas as pd
import pytest

from services.correlation_engine import correlate_flows
from services.correlation_service import CorrelationService


def test_correlate_flows_three_synthetic_incidents():
    """
    Assert three expected incident types are discovered:
    1. Port scan: one source contacting 20+ distinct ports in <60s, which classifier called benign.
    2. Fan-in: 30 distinct sources contacting a single dest IP:port in <60s.
    3. Suspicious burst: flagged flows from a single source within gap_s=300.
    4. Normal benign traffic that should not trigger incidents.
    """
    base_time = datetime(2026, 10, 15, 10, 0, 0)
    flows = []
    flow_id = 1

    # 1. Port scan: 192.168.1.100 hits 25 distinct ports in 30 seconds (all labeled benign)
    for port in range(1000, 1025):
        flows.append(
            {
                "id": flow_id,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.99",
                "dst_port": port,
                "ts": (base_time + timedelta(seconds=port - 1000)).strftime("%d/%m/%Y %H:%M:%S"),
                "score": 0.02,
                "label": "benign",
            }
        )
        flow_id += 1

    # 2. Fan-in: 30 distinct sources targeting 10.0.0.200:80 in 20 seconds
    for src_idx in range(1, 31):
        flows.append(
            {
                "id": flow_id,
                "src_ip": f"172.16.1.{src_idx}",
                "dst_ip": "10.0.0.200",
                "dst_port": 80,
                "ts": (base_time + timedelta(seconds=src_idx % 20)).strftime("%d/%m/%Y %H:%M:%S"),
                "score": 0.05,
                "label": "benign",
            }
        )
        flow_id += 1

    # 3. Suspicious burst: 5 suspicious flows from 192.168.5.55
    for b_idx in range(5):
        flows.append(
            {
                "id": flow_id,
                "src_ip": "192.168.5.55",
                "dst_ip": "10.0.0.5",
                "dst_port": 443,
                "ts": (base_time + timedelta(seconds=b_idx * 10)).strftime("%d/%m/%Y %H:%M:%S"),
                "score": 0.88,
                "label": "suspicious",
            }
        )
        flow_id += 1

    # 4. Normal benign traffic: occasional scattered flows
    for n_idx in range(10):
        flows.append(
            {
                "id": flow_id,
                "src_ip": f"192.168.10.{n_idx + 1}",
                "dst_ip": f"10.0.1.{n_idx + 1}",
                "dst_port": 443,
                "ts": (base_time + timedelta(seconds=n_idx * 50)).strftime("%d/%m/%Y %H:%M:%S"),
                "score": 0.001,
                "label": "benign",
            }
        )
        flow_id += 1

    df = pd.DataFrame(flows)
    incidents = correlate_flows(df)

    assert len(incidents) >= 3

    all_kinds = set()
    for inc in incidents:
        all_kinds.update(inc["kinds"])

    assert "port_scan" in all_kinds
    assert "fan_in" in all_kinds
    assert "suspicious_burst" in all_kinds


def test_single_flow_burst_suppressed_when_in_scan():
    # If a flow triggers a port scan and is suspicious, it should NOT generate an extra single-flow burst incident
    base_time = datetime(2026, 10, 15, 10, 0, 0)
    flows = []
    # 25 distinct ports from 192.168.1.50
    for port in range(25):
        flows.append(
            {
                "id": port + 1,
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.1",
                "dst_port": 8000 + port,
                "ts": (base_time + timedelta(seconds=port)).strftime("%d/%m/%Y %H:%M:%S"),
                "score": 0.9 if port == 0 else 0.01,
                "label": "suspicious" if port == 0 else "benign",
            }
        )
    df = pd.DataFrame(flows)
    incidents = correlate_flows(df)

    # Should have port_scan, but not a separate suspicious_burst for the single flow
    kinds = [inc["kinds"] for inc in incidents]
    assert any("port_scan" in k for k in kinds)
    # The merged incident or remaining incident contains port_scan
    assert not any(inc["kinds"] == ["suspicious_burst"] and inc["flow_count"] == 1 for inc in incidents)


def test_reasons_deduplication():
    # Verify that identical reasons are not duplicated in incidents
    base_time = datetime(2026, 10, 15, 10, 0, 0)
    flows = [
        {
            "id": 1,
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "ts": base_time.strftime("%d/%m/%Y %H:%M:%S"),
            "score": 0.8,
            "label": "suspicious",
        },
        {
            "id": 2,
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "ts": (base_time + timedelta(seconds=10)).strftime("%d/%m/%Y %H:%M:%S"),
            "score": 0.9,
            "label": "suspicious",
        },
    ]
    df = pd.DataFrame(flows)
    incidents = correlate_flows(df)
    for inc in incidents:
        assert len(inc["reasons"]) == len(set(inc["reasons"]))


def test_correlate_flows_50k_scale_performance():
    # Build 50,000 synthetic flows to test inverted-index scaling
    base_time = datetime(2026, 10, 15, 0, 0, 0)
    n = 50000

    timestamps = [base_time + timedelta(seconds=i % 3600) for i in range(n)]
    src_ips = [f"192.168.{i % 250}.{(i * 7) % 250}" for i in range(n)]
    dst_ips = [f"10.0.{i % 50}.{(i * 3) % 250}" for i in range(n)]
    dst_ports = [(i % 1000) + 1 for i in range(n)]
    scores = np.random.uniform(0.0, 0.1, size=n)
    labels = np.array(["benign"] * n, dtype=object)

    # Inject 5 bursts
    for b in range(5):
        burst_indices = range(b * 1000, b * 1000 + 20)
        labels[burst_indices] = "suspicious"
        scores[burst_indices] = 0.85
        for bi in burst_indices:
            src_ips[bi] = f"172.16.99.{b}"

    df = pd.DataFrame(
        {
            "id": np.arange(1, n + 1),
            "src_ip": src_ips,
            "dst_ip": dst_ips,
            "dst_port": dst_ports,
            "ts": timestamps,
            "score": scores,
            "label": labels,
        }
    )

    start_time = time.perf_counter()
    incidents = correlate_flows(df)
    elapsed = time.perf_counter() - start_time

    assert elapsed < 5.0, f"Correlation on 50,000 flows took {elapsed:.2f}s (expected < 5.0s)"
    assert isinstance(incidents, list)


@pytest.mark.anyio
async def test_correlate_upload_skips_when_missing_ip_or_ts(monkeypatch):
    from core.database import mongodb

    service = CorrelationService()

    class FakeCursor:
        async def to_list(self, length=None):
            return [
                {"flow_id": 1, "upload_id": "up-1", "score": 0.5, "label": "suspicious"},
                {"flow_id": 2, "upload_id": "up-1", "score": 0.1, "label": "benign"},
            ]

    class FakeColl:
        def find(self, query, projection=None):
            return FakeCursor()

    monkeypatch.setattr(mongodb, "get_collection", lambda name: FakeColl())

    incidents, warnings = await service.correlate_upload("up-1")
    assert len(incidents) == 0
    assert any("Upload lacks IP or timestamp metadata; correlation skipped." in w for w in warnings)
