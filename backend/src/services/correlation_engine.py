import numpy as np
import pandas as pd


def _inc(kind, reason, h):
    scores = h["score"].dropna()
    return {
        "kinds": {kind},
        "reasons": [reason],
        "flow_ids": set(h["id"].tolist()),
        "start": h["ts"].min(),
        "end": h["ts"].max(),
        "max_score": float(scores.max()) if len(scores) else 0.0,
        "src_ips": set(h["src_ip"]),
        "dst_ips": set(h["dst_ip"].dropna()),
    }


def _merge(a, b):
    # De-duplicate reasons while preserving order
    combined_reasons = list(dict.fromkeys(a["reasons"] + b["reasons"]))
    return {
        "kinds": a["kinds"] | b["kinds"],
        "reasons": combined_reasons,
        "flow_ids": a["flow_ids"] | b["flow_ids"],
        "start": min(a["start"], b["start"]),
        "end": max(a["end"], b["end"]),
        "max_score": max(a["max_score"], b["max_score"]),
        "src_ips": a["src_ips"] | b["src_ips"],
        "dst_ips": a["dst_ips"] | b["dst_ips"],
    }


def correlate_flows(
    df,
    gap_s=300,
    scan_ports=20,
    scan_window_s=60,
    fan_in_sources=20,
    fan_in_window_s=60,
):
    # df columns: id, src_ip, dst_ip, dst_port, ts, score, label ("benign"/"suspicious"/"invalid")
    df = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df["ts"]):
        df["ts"] = pd.to_datetime(df["ts"], dayfirst=True, errors="coerce")
    df = df.dropna(subset=["ts", "src_ip"]).sort_values("ts")


    if df.empty:
        return []

    # Valid non-invalid flows for port-scan and fan-in rules
    valid_df = df[df["label"] != "invalid"].copy()
    if not valid_df.empty:
        valid_secs = (valid_df["ts"] - valid_df["ts"].min()).dt.total_seconds()
        valid_df["_sbin"] = (valid_secs // scan_window_s).astype(int)
        valid_df["_fbin"] = (valid_secs // fan_in_window_s).astype(int)

    # Rule 2: port scan = one source touching many distinct ports in a short window
    scan_incidents = []
    if not valid_df.empty:
        for (src, b), g in valid_df.groupby(["src_ip", "_sbin"]):
            n = g["dst_port"].nunique()
            if n >= scan_ports:
                scan_incidents.append(
                    _inc("port_scan", f"{src} contacted {n} distinct ports in {scan_window_s}s", g)
                )

    # Rule 3: fan-in = many sources hitting one destination/port in a short window
    fan_in_incidents = []
    if not valid_df.empty:
        for (dst, port, b), g in valid_df.groupby(["dst_ip", "dst_port", "_fbin"]):
            n = g["src_ip"].nunique()
            if n >= fan_in_sources:
                fan_in_incidents.append(
                    _inc("fan_in", f"{n} sources targeted {dst}:{port} in {fan_in_window_s}s", g)
                )

    # Set of flow IDs that already participate in fan_in or port_scan
    scan_or_fanin_flow_ids = set()
    for inc in scan_incidents:
        scan_or_fanin_flow_ids.update(inc["flow_ids"])
    for inc in fan_in_incidents:
        scan_or_fanin_flow_ids.update(inc["flow_ids"])

    # Rule 1: suspicious flows from one source, split when the gap exceeds gap_s
    burst_incidents = []
    s = df[df["label"] == "suspicious"]
    if not s.empty:
        for src, g in s.groupby("src_ip"):
            brk = g["ts"].diff().dt.total_seconds().fillna(np.inf) > gap_s
            for _, h in g.groupby(brk.cumsum()):
                flow_ids = set(h["id"].tolist())
                # Skip single-flow burst if that flow already belongs to a fan_in or port_scan incident
                if len(flow_ids) == 1 and (flow_ids & scan_or_fanin_flow_ids):
                    continue
                burst_incidents.append(_inc("suspicious_burst", f"{len(h)} flagged flows from {src}", h))

    # All candidate incidents
    all_candidates = scan_incidents + fan_in_incidents + burst_incidents
    if not all_candidates:
        return []

    # Rule 4: merge incidents that share any flow using an inverted index (flow_id -> incident_id)
    flow_to_inc: dict[int, int] = {}
    incidents_by_id: dict[int, dict] = {}
    next_inc_id = 0

    for inc in all_candidates:
        matching_inc_ids = {flow_to_inc[fid] for fid in inc["flow_ids"] if fid in flow_to_inc}

        if not matching_inc_ids:
            inc_id = next_inc_id
            next_inc_id += 1
            incidents_by_id[inc_id] = inc
            for fid in inc["flow_ids"]:
                flow_to_inc[fid] = inc_id
        else:
            target_id = min(matching_inc_ids)
            current_inc = inc
            for mid in matching_inc_ids:
                current_inc = _merge(current_inc, incidents_by_id.pop(mid))
            incidents_by_id[target_id] = current_inc
            for fid in current_inc["flow_ids"]:
                flow_to_inc[fid] = target_id

    merged = list(incidents_by_id.values())

    return [
        {
            "kinds": sorted(m["kinds"]),
            "start": str(m["start"]),
            "end": str(m["end"]),
            "flow_count": len(m["flow_ids"]),
            "max_score": m["max_score"],
            "src_ips": sorted(m["src_ips"])[:10],
            "dst_ips": sorted(m["dst_ips"])[:10],
            "reasons": list(dict.fromkeys(m["reasons"])),
            "flow_ids": sorted(m["flow_ids"]),
        }
        for m in sorted(merged, key=lambda m: m["start"])
    ]
