
import numpy as np
import pandas as pd

def _inc(kind, reason, h):
    scores = h["score"].dropna()
    return {"kinds": {kind}, "reasons": [reason], "flow_ids": set(h["id"].tolist()),
            "start": h["ts"].min(), "end": h["ts"].max(),
            "max_score": float(scores.max()) if len(scores) else 0.0,
            "src_ips": set(h["src_ip"]), "dst_ips": set(h["dst_ip"].dropna())}

def _merge(a, b):
    return {"kinds": a["kinds"] | b["kinds"], "reasons": a["reasons"] + b["reasons"],
            "flow_ids": a["flow_ids"] | b["flow_ids"],
            "start": min(a["start"], b["start"]), "end": max(a["end"], b["end"]),
            "max_score": max(a["max_score"], b["max_score"]),
            "src_ips": a["src_ips"] | b["src_ips"], "dst_ips": a["dst_ips"] | b["dst_ips"]}

def correlate_flows(df, gap_s=300, scan_ports=20, scan_window_s=60,
                    fan_in_sources=20, fan_in_window_s=60):
    # df columns: id, src_ip, dst_ip, dst_port, ts, score, label ("benign"/"suspicious"/"invalid")
    df = df.copy()
    df["ts"] = pd.to_datetime(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts", "src_ip"]).sort_values("ts")
    if df.empty:
        return []
    secs = (df["ts"] - df["ts"].min()).dt.total_seconds()
    found = []

    # Rule 1: suspicious flows from one source, split when the gap exceeds gap_s
    s = df[df["label"] == "suspicious"]
    for src, g in s.groupby("src_ip"):
        brk = g["ts"].diff().dt.total_seconds().fillna(np.inf) > gap_s
        for _, h in g.groupby(brk.cumsum()):
            found.append(_inc("suspicious_burst", f"{len(h)} flagged flows from {src}", h))

    # Rule 2: port scan = one source touching many distinct ports in a short window.
    # Uses ALL flows (even ones the classifier called benign), since scans look benign per flow.
    df["_sbin"] = (secs // scan_window_s).astype(int)
    for (src, b), g in df.groupby(["src_ip", "_sbin"]):
        n = g["dst_port"].nunique()
        if n >= scan_ports:
            found.append(_inc("port_scan", f"{src} contacted {n} distinct ports in {scan_window_s}s", g))

    # Rule 3: fan-in = many sources hitting one destination/port in a short window
    df["_fbin"] = (secs // fan_in_window_s).astype(int)
    for (dst, port, b), g in df.groupby(["dst_ip", "dst_port", "_fbin"]):
        n = g["src_ip"].nunique()
        if n >= fan_in_sources:
            found.append(_inc("fan_in", f"{n} sources targeted {dst}:{port} in {fan_in_window_s}s", g))

    # Rule 4: merge incidents that share any flow
    merged = []
    for inc in found:
        hits = [m for m in merged if m["flow_ids"] & inc["flow_ids"]]
        for m in hits:
            merged.remove(m)
            inc = _merge(inc, m)
        merged.append(inc)

    return [{"kinds": sorted(m["kinds"]), "start": str(m["start"]), "end": str(m["end"]),
             "flow_count": len(m["flow_ids"]), "max_score": m["max_score"],
             "src_ips": sorted(m["src_ips"])[:10], "dst_ips": sorted(m["dst_ips"])[:10],
             "reasons": m["reasons"], "flow_ids": sorted(m["flow_ids"])}
            for m in sorted(merged, key=lambda m: m["start"])]
