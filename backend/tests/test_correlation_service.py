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


def test_chain_merge():
    # A shares with B, B shares with C, A and C do not share flows directly
    # Verifies transitive / chain merging in inverted index
    base_time = datetime(2026, 10, 15, 10, 0, 0)
    flows = [
        # Burst 1: flow 1 and 2
        {"id": 1, "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": base_time.strftime("%d/%m/%Y %H:%M:%S"), "score": 0.9, "label": "suspicious"},
        {"id": 2, "src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": (base_time + timedelta(seconds=1)).strftime("%d/%m/%Y %H:%M:%S"), "score": 0.9, "label": "suspicious"},
    ]
    # Port scan from 10.10.10.10 touching 25 ports, including flow 2 and flow 124
    for p in range(25):
        fid = 2 if p == 0 else (100 + p)
        flows.append({
            "id": fid,
            "src_ip": "10.10.10.10",
            "dst_ip": "10.0.0.2",
            "dst_port": 1000 + p,
            "ts": (base_time + timedelta(seconds=p)).strftime("%d/%m/%Y %H:%M:%S"),
            "score": 0.1,
            "label": "benign",
        })
    # Fan-in targeting 10.0.0.99:443 from 25 sources, including flow 124
    for s in range(25):
        fid = 124 if s == 0 else (200 + s)
        flows.append({
            "id": fid,
            "src_ip": f"172.16.2.{s}",
            "dst_ip": "10.0.0.99",
            "dst_port": 443,
            "ts": (base_time + timedelta(seconds=s)).strftime("%d/%m/%Y %H:%M:%S"),
            "score": 0.1,
            "label": "benign",
        })

    df = pd.DataFrame(flows)
    incidents = correlate_flows(df)
    # The chain connects burst -> port_scan -> fan_in into a single incident
    assert len(incidents) == 1
    assert set(incidents[0]["kinds"]) == {"fan_in", "port_scan", "suspicious_burst"}


def test_correlate_flows_50k_scale_performance():
    # Build 50,000 synthetic flows with HIGH CARDINALITY:
    # 5,000 distinct source IPs, 2,000 distinct destination ports
    base_time = datetime(2026, 10, 15, 0, 0, 0)
    n = 50000

    timestamps = [base_time + timedelta(seconds=i % 3600) for i in range(n)]
    src_ips = [f"192.168.{i % 5000 // 256}.{i % 256}" for i in range(n)]
    dst_ips = [f"10.0.{(i * 13) % 250}.{(i * 3) % 250}" for i in range(n)]
    dst_ports = [(i % 2000) + 1 for i in range(n)]
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
    assert len(incidents) == 5


def test_correlate_flows_50k_scans_and_fan_ins():
    """
    Second 50k benchmark:
    - 200 sources scanning 30 distinct ports each (6,000 flows)
    - 50 targets receiving fan-in from 25 sources each (1,250 flows)
    - 42,750 background benign flows
    Asserts expected incidents are found and measures execution time.
    """
    base_time = datetime(2026, 10, 15, 10, 0, 0)
    flows = []
    flow_id = 1

    # 1. 200 sources scanning 30 ports each (6,000 flows)
    for s in range(200):
        src_ip = f"10.100.{s // 256}.{s % 256}"
        dst_ip = f"192.168.100.{s}"
        for p in range(30):
            flows.append({
                "id": flow_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": 1000 + p,
                "ts": base_time + timedelta(seconds=p % 30),
                "score": 0.01,
                "label": "benign",
            })
            flow_id += 1

    # 2. 50 targets receiving fan-in from 25 sources (1,250 flows)
    for t in range(50):
        dst_ip = f"10.200.{t // 256}.{t % 256}"
        for s in range(25):
            flows.append({
                "id": flow_id,
                "src_ip": f"172.20.{t}.{s}",
                "dst_ip": dst_ip,
                "dst_port": 80,
                "ts": base_time + timedelta(seconds=s % 30),
                "score": 0.01,
                "label": "benign",
            })
            flow_id += 1

    # 3. Background benign flows (42,750 flows)
    rem = 50000 - len(flows)
    for i in range(rem):
        flows.append({
            "id": flow_id,
            "src_ip": f"192.168.{2 + (i // 250)}.{i % 250}",
            "dst_ip": f"10.1.{i % 100}.{i % 250}",
            "dst_port": 8000 + (i % 10),
            "ts": base_time + timedelta(seconds=60 + (i % 3500)),
            "score": 0.005,
            "label": "benign",
        })
        flow_id += 1

    df = pd.DataFrame(flows)
    assert len(df) == 50000

    start_time = time.perf_counter()
    incidents = correlate_flows(df)
    elapsed = time.perf_counter() - start_time

    port_scans = [inc for inc in incidents if "port_scan" in inc["kinds"]]
    fan_ins = [inc for inc in incidents if "fan_in" in inc["kinds"]]

    print(f"\n[BENCHMARK] 50k flows (200 scans, 50 fan-ins): elapsed={elapsed:.3f}s, incidents={len(incidents)}")
    assert len(port_scans) == 200, f"Expected 200 port scans, got {len(port_scans)}"
    assert len(fan_ins) == 50, f"Expected 50 fan-ins, got {len(fan_ins)}"
    assert len(incidents) == 250
    assert elapsed < 5.0, f"Expected < 5.0s, took {elapsed:.2f}s"



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


@pytest.mark.anyio
async def test_assume_no_ampm_business_hours_unshifted_and_shifted(monkeypatch):
    from core.config import settings
    from core.database import mongodb

    service = CorrelationService()

    docs = [
        {"flow_id": 1, "upload_id": "up-clock", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 01:30", "score": 0.8, "label": "suspicious"},
        {"flow_id": 2, "upload_id": "up-clock", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 01:35", "score": 0.9, "label": "suspicious"},
        {"flow_id": 3, "upload_id": "up-clock", "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 01:36", "score": 0.85, "label": "suspicious"},
    ]

    class FakeCursor:
        async def to_list(self, length=None):
            return docs

    class FakeColl:
        def find(self, query, projection=None):
            return FakeCursor()
        async def delete_many(self, *args, **kwargs):
            pass
        async def update_many(self, *args, **kwargs):
            pass
        async def update_one(self, *args, **kwargs):
            pass
        async def insert_one(self, *args, **kwargs):
            pass

    monkeypatch.setattr(mongodb, "get_collection", lambda name: FakeColl())

    # 1. Flag OFF: hour remains 01
    monkeypatch.setattr(settings, "ASSUME_NO_AMPM_BUSINESS_HOURS", False)
    incs_off, warns_off = await service.correlate_upload("up-clock")
    assert not any("Assumed 12-hour PM clock" in w for w in warns_off)
    assert len(incs_off) == 1
    assert "01:30" in incs_off[0]["start"]
    assert incs_off[0]["time_shift_applied"] is False

    # 2. Flag ON: hour 1 shifted to 13 (1:30 -> 13:30)
    monkeypatch.setattr(settings, "ASSUME_NO_AMPM_BUSINESS_HOURS", True)
    monkeypatch.setattr(settings, "AMPM_PM_HOURS_START", 1)
    monkeypatch.setattr(settings, "AMPM_PM_HOURS_END", 7)
    incs_on, warns_on = await service.correlate_upload("up-clock")
    assert any("Assumed 12-hour PM clock" in w and "shifted 3 row(s)" in w for w in warns_on)
    assert len(incs_on) == 1
    assert "13:30" in incs_on[0]["start"]
    assert incs_on[0]["time_shift_applied"] is True


@pytest.mark.anyio
async def test_mixed_morning_afternoon_sorting_with_clock_fix(monkeypatch):
    from core.config import settings
    from core.database import mongodb

    service = CorrelationService()

    # Flow 1-3 at 09:30 (morning), Flow 4-6 at 01:15 (afternoon missing PM tag)
    docs = [
        {"flow_id": 1, "upload_id": "up-mixed", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 09:30", "score": 0.85, "label": "suspicious"},
        {"flow_id": 2, "upload_id": "up-mixed", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 09:31", "score": 0.85, "label": "suspicious"},
        {"flow_id": 3, "upload_id": "up-mixed", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 09:32", "score": 0.85, "label": "suspicious"},
        {"flow_id": 4, "upload_id": "up-mixed", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 01:15", "score": 0.85, "label": "suspicious"},
        {"flow_id": 5, "upload_id": "up-mixed", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 01:16", "score": 0.85, "label": "suspicious"},
        {"flow_id": 6, "upload_id": "up-mixed", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 80, "ts": "07/07/2017 01:17", "score": 0.85, "label": "suspicious"},
    ]

    class FakeCursor:
        async def to_list(self, length=None):
            return docs

    class FakeColl:
        def find(self, query, projection=None):
            return FakeCursor()
        async def delete_many(self, *args, **kwargs):
            pass
        async def update_many(self, *args, **kwargs):
            pass
        async def update_one(self, *args, **kwargs):
            pass
        async def insert_one(self, *args, **kwargs):
            pass

    monkeypatch.setattr(mongodb, "get_collection", lambda name: FakeColl())

    monkeypatch.setattr(settings, "ASSUME_NO_AMPM_BUSINESS_HOURS", True)
    monkeypatch.setattr(settings, "AMPM_PM_HOURS_START", 1)
    monkeypatch.setattr(settings, "AMPM_PM_HOURS_END", 7)

    incs, warns = await service.correlate_upload("up-mixed")
    # With flag ON: 09:30 is morning, 01:15 becomes 13:15
    # Since gap between 09:30 and 13:15 is > 300s (gap_s=300), they form 2 bursts.
    # Earliest incident start should be 09:30, second should be 13:15!
    assert len(incs) == 2
    starts = [inc["start"] for inc in incs]
    assert any("09:30" in s for s in starts)
    assert any("13:15" in s for s in starts)
    assert sorted(starts) == starts, f"Expected chronologically sorted incidents, got {starts}"


