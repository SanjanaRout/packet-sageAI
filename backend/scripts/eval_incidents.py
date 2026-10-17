"""
scripts/eval_incidents.py

NOTE: This script uses ground-truth labels from the CIC-IDS2017 dataset for lab
evaluation and verification only. It is a standalone evaluation utility and NOT
part of the production API service or user-facing incident workflow.

Joins flow records from uploaded CSVs to correlated incidents in MongoDB (or
evaluates correlation in-memory against candidate settings) to report:
1. Fraction of flows with a ground-truth Label other than BENIGN.
2. Dominant ground-truth label for each incident.
3. Attack flow coverage: per attack label, how many flows fall in any incident.
4. Precision metrics across varying port scan and burst threshold settings.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pandas as pd
from pymongo import MongoClient

# Add src to pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.config import settings
from services.correlation_engine import correlate_flows
from services.model_service import model_service
from services.flow_service import score_chunk_sync


def find_label_col(df: pd.DataFrame) -> str:
    for c in df.columns:
        if c.strip().lower() == "label":
            return c
    raise ValueError(f"No 'Label' column found in DataFrame columns: {list(df.columns)}")


def evaluate_upload_from_db(upload_id: str, csv_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates an existing upload in MongoDB by joining uploads/{upload_id}.csv (or provided csv_path)
    to incident flow_ids.
    """
    if csv_path is None:
        csv_path = os.path.join("uploads", f"{upload_id}.csv")

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found at: {csv_path}")

    df = pd.read_csv(csv_path)
    label_col = find_label_col(df)

    # Clean labels
    df["gt_label"] = df[label_col].astype(str).str.strip()
    df["flow_id"] = np.arange(1, len(df) + 1)

    mongo_client = MongoClient("mongodb://user:password@localhost:27017/?authSource=admin")
    db = mongo_client["packet_sage"]
    incidents = list(db["incidents"].find({"upload_id": upload_id}))

    print(f"\n================================================================================")
    print(f"LAB EVALUATION: Upload {upload_id} ({os.path.basename(csv_path)})")
    print(f"Total flows: {len(df)} | Incidents formed: {len(incidents)}")
    print(f"================================================================================")

    incident_summaries = []
    all_incident_flow_ids: Set[int] = set()

    for i, inc in enumerate(incidents):
        fids = set(inc.get("flow_ids", []))
        all_incident_flow_ids.update(fids)

        sub_labels = df[df["flow_id"].isin(fids)]["gt_label"]
        total_in_inc = len(sub_labels)

        attack_mask = sub_labels.str.upper() != "BENIGN"
        attack_count = int(attack_mask.sum())
        attack_fraction = (attack_count / total_in_inc) if total_in_inc > 0 else 0.0

        label_counts = Counter(sub_labels)
        dominant_label, dominant_count = label_counts.most_common(1)[0] if label_counts else ("NONE", 0)

        summary = {
            "index": i + 1,
            "incident_id": inc.get("incident_id"),
            "kinds": inc.get("kinds", []),
            "flow_count": total_in_inc,
            "attack_flows": attack_count,
            "attack_fraction": attack_fraction,
            "dominant_label": dominant_label,
            "dominant_count": dominant_count,
            "first_reason": inc.get("reasons", ["N/A"])[0],
        }
        incident_summaries.append(summary)

        print(
            f"[{i+1:02d}] {inc.get('incident_id')} | Kinds: {inc.get('kinds')} | "
            f"Flows: {total_in_inc:5d} | Attack Frac: {attack_fraction:6.2%} ({attack_count}/{total_in_inc}) | "
            f"Dominant: {dominant_label} ({dominant_count}) | Reason: {inc.get('reasons', ['N/A'])[0]}"
        )

    # Per-attack label coverage
    print("\n--- Attack Flow Coverage ---")
    attack_labels = [lbl for lbl in df["gt_label"].unique() if lbl.upper() != "BENIGN"]
    coverage_report = {}

    if not attack_labels:
        print("No ground-truth attack flows in this dataset (100% BENIGN).")
    else:
        for att_lbl in sorted(attack_labels):
            att_mask = df["gt_label"] == att_lbl
            total_att = int(att_mask.sum())
            in_inc_count = int((att_mask & df["flow_id"].isin(all_incident_flow_ids)).sum())
            cov_ratio = in_inc_count / total_att if total_att > 0 else 0.0
            coverage_report[att_lbl] = {
                "total": total_att,
                "in_incidents": in_inc_count,
                "coverage": cov_ratio,
            }
            print(f"  {att_lbl:25s}: {in_inc_count:5d} / {total_att:5d} ({cov_ratio:6.2%}) covered in incidents")

    return {
        "upload_id": upload_id,
        "csv_path": csv_path,
        "total_flows": len(df),
        "incidents": incident_summaries,
        "coverage": coverage_report,
    }


def evaluate_file_with_params(
    csv_path: str,
    scan_min_ports: int = 20,
    scan_max_dst_port: Optional[int] = None,
    min_burst_flows: int = 1,
    isolated_flow_max: int = 0,
    assume_no_ampm: bool = False,
    blind_classifier: bool = False,
) -> Dict[str, Any]:
    """
    Evaluates correlation directly on a raw CSV file under specific rule configurations.
    Used for precision/coverage cross-checking and sensitivity sweeps.
    """
    df = pd.read_csv(csv_path)
    label_col = find_label_col(df)
    df["gt_label"] = df[label_col].astype(str).str.strip()
    df["id"] = np.arange(1, len(df) + 1)

    # Normalize columns
    orig_cols = {c.strip().lower(): c for c in df.columns}
    src_ip_col = orig_cols.get("src_ip") or orig_cols.get("source ip") or orig_cols.get("source_ip")
    dst_ip_col = orig_cols.get("dst_ip") or orig_cols.get("destination ip") or orig_cols.get("destination_ip")
    dst_port_col = orig_cols.get("dst_port") or orig_cols.get("destination port") or orig_cols.get("destination_port")
    ts_col = orig_cols.get("timestamp") or orig_cols.get("ts") or orig_cols.get("time")

    corr_df = pd.DataFrame({
        "id": df["id"],
        "src_ip": df[src_ip_col] if src_ip_col else None,
        "dst_ip": df[dst_ip_col] if dst_ip_col else None,
        "dst_port": pd.to_numeric(df[dst_port_col], errors="coerce") if dst_port_col else None,
        "ts": df[ts_col] if ts_col else None,
    })

    # Parse timestamps
    corr_df["ts"] = pd.to_datetime(corr_df["ts"], format="%d/%m/%Y %H:%M", errors="coerce")
    if assume_no_ampm:
        mask = corr_df["ts"].dt.hour.between(1, 7, inclusive="both")
        corr_df.loc[mask, "ts"] += pd.Timedelta(hours=12)

    # Score with model
    if not model_service.is_loaded:
        model_service.load()

    chunk_df = df.copy()
    chunk_df.columns = [c.strip().lower() for c in chunk_df.columns]
    _, scores, labels, _ = score_chunk_sync(
        chunk_df,
        model_service.features,
        model_service.model,
        model_service.threshold,
        model_service.novelty_model,
        model_service.novelty_medians,
        model_service.novelty_threshold,
    )
    corr_df["score"] = scores
    corr_df["label"] = labels

    incidents, isolated_flow_ids = correlate_flows(
        corr_df,
        scan_ports=scan_min_ports,
        scan_max_dst_port=scan_max_dst_port,
        min_burst_flows=min_burst_flows,
        isolated_flow_max=isolated_flow_max,
        blind_classifier=blind_classifier,
        return_isolated=True,
    )

    port_scan_incidents = [inc for inc in incidents if "port_scan" in inc["kinds"]]
    zero_attack_scans = 0
    all_scan_flow_ids: Set[int] = set()
    all_inc_flow_ids: Set[int] = set()

    for inc in incidents:
        all_inc_flow_ids.update(inc["flow_ids"])

    for inc in port_scan_incidents:
        fids = inc["flow_ids"]
        all_scan_flow_ids.update(fids)
        sub_labels = df[df["id"].isin(fids)]["gt_label"]
        attack_count = (sub_labels.str.upper() != "BENIGN").sum()
        if attack_count == 0:
            zero_attack_scans += 1

    portscan_attack_mask = df["gt_label"].str.contains("PortScan", case=False, regex=False)
    total_portscan_attack = int(portscan_attack_mask.sum())
    covered_portscan_attack = int((portscan_attack_mask & df["id"].isin(all_inc_flow_ids)).sum())
    coverage_ratio = (covered_portscan_attack / total_portscan_attack) if total_portscan_attack > 0 else 1.0

    # Combined flow IDs: incidents + isolated list
    combined_flow_ids = all_inc_flow_ids | set(isolated_flow_ids)

    # Per-label coverage across all attack types
    attack_labels = [lbl for lbl in df["gt_label"].unique() if lbl.upper() != "BENIGN"]
    per_label_coverage = {}
    per_label_combined_coverage = {}
    for att_lbl in sorted(attack_labels):
        att_mask = df["gt_label"] == att_lbl
        tot_att = int(att_mask.sum())
        cov_att = int((att_mask & df["id"].isin(all_inc_flow_ids)).sum())
        cov_comb = int((att_mask & df["id"].isin(combined_flow_ids)).sum())
        per_label_coverage[att_lbl] = {
            "total": tot_att,
            "covered": cov_att,
            "coverage": (cov_att / tot_att) if tot_att > 0 else 0.0,
        }
        per_label_combined_coverage[att_lbl] = {
            "total": tot_att,
            "covered": cov_comb,
            "coverage": (cov_comb / tot_att) if tot_att > 0 else 0.0,
        }


    return {
        "file": os.path.basename(csv_path),
        "total_incidents": len(incidents),
        "port_scan_incidents": len(port_scan_incidents),
        "zero_attack_scans": zero_attack_scans,
        "total_portscan_flows": total_portscan_attack,
        "covered_portscan_flows": covered_portscan_attack,
        "portscan_coverage": coverage_ratio,
        "per_label_coverage": per_label_coverage,
        "per_label_combined_coverage": per_label_combined_coverage,
        "isolated_flow_ids": isolated_flow_ids,
        "isolated_flow_count": len(isolated_flow_ids),
        "port_scan_details": port_scan_incidents,
        "all_incidents": incidents,
        "df": df,
        "corr_df": corr_df,
    }



def run_port_comparison(
    csv_paths: Optional[List[str]] = None,
    ports: Optional[List[Optional[int]]] = None,
    assume_no_ampm: bool = True,
) -> None:
    """
    Sweeps SCAN_MAX_DST_PORT across candidate thresholds and prints a comparison table.
    """
    if csv_paths is None:
        csv_paths = [
            "tests/data/portscan_slice.csv",
            "tests/data/portscan_window_dense.csv",
        ]
    if ports is None:
        ports = [None, 1024, 10000, 32768, 49152]

    print("\n=========================================================================================================")
    print("EXTENDED SCAN_MAX_DST_PORT COMPARISON (Lab evaluation only; Friday windows)")
    print("=========================================================================================================")
    print(f"{'File':<28} | {'SCAN_MAX_DST_PORT':<18} | {'PortScan Incs':<14} | {'Zero-Attack Incs':<16} | {'PortScan Flow Cov':<22}")
    print("-" * 105)

    for pth in csv_paths:
        if not os.path.exists(pth):
            print(f"Skipping {pth}: file not found.")
            continue
        fname = os.path.basename(pth)
        for p in ports:
            p_str = "None (default)" if p is None else str(p)
            res = evaluate_file_with_params(pth, scan_max_dst_port=p, assume_no_ampm=assume_no_ampm)
            incs = res["port_scan_incidents"]
            zero_att = res["zero_attack_scans"]
            cov_flows = res["covered_portscan_flows"]
            tot_flows = res["total_portscan_flows"]
            cov_pct = res["portscan_coverage"]
            cov_str = f"{cov_flows}/{tot_flows} ({cov_pct:.2%})" if tot_flows > 0 else "N/A (0 GT flows)"
            print(f"{fname:<28} | {p_str:<18} | {incs:<14} | {zero_att:<16} | {cov_str:<22}")
    print("=========================================================================================================")


def main():
    parser = argparse.ArgumentParser(description="Evaluate incidents against ground-truth labels (Lab evaluation only)")
    parser.add_argument("--upload_id", type=str, help="Upload ID in MongoDB")
    parser.add_argument("--csv", type=str, help="Path to raw CSV file")
    parser.add_argument("--compare-ports", action="store_true", help="Run extended SCAN_MAX_DST_PORT comparison sweep")
    args = parser.parse_args()

    if args.compare_ports:
        run_port_comparison()
    elif args.upload_id:
        evaluate_upload_from_db(args.upload_id, args.csv)
    elif args.csv:
        res = evaluate_file_with_params(args.csv)
        print(f"\nResults for {args.csv}:")
        print(f"  Total incidents: {res['total_incidents']}")
        print(f"  Port scan incidents: {res['port_scan_incidents']} ({res['zero_attack_scans']} with zero attack flows)")
        print(f"  PortScan attack flow coverage: {res['covered_portscan_flows']}/{res['total_portscan_flows']} ({res['portscan_coverage']:.2%})")
    else:
        # Default: evaluate all 3 standard test datasets
        test_files = [
            "tests/data/sample_real_flows.csv",
            "tests/data/portscan_slice.csv",
            "tests/data/portscan_window_dense.csv",
        ]
        for tf in test_files:
            if os.path.exists(tf):
                res = evaluate_file_with_params(tf, assume_no_ampm=True)
                print(f"\n==================== {tf} ====================")
                print(f"Total incidents: {res['total_incidents']}")
                print(f"Port scan incidents: {res['port_scan_incidents']} ({res['zero_attack_scans']} with zero attack flows)")
                print(f"PortScan flow coverage: {res['covered_portscan_flows']}/{res['total_portscan_flows']} ({res['portscan_coverage']:.2%})")


if __name__ == "__main__":
    main()

