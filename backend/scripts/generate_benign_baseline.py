"""
scripts/generate_benign_baseline.py

Deterministic utility to compute and export reference quantiles and mean/std
for all numeric model features computed exclusively from benign network flows.
Used for statistical deviation evidence in GenAI incident explanations.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

# Add src to pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.config import settings


def find_label_col(df: pd.DataFrame) -> str:
    for c in df.columns:
        if c.strip().lower() == "label":
            return c
    raise ValueError(f"No 'Label' column found in columns: {list(df.columns)}")


def generate_benign_baseline(
    data_paths: Optional[List[str]] = None,
    output_path: Optional[str] = None,
    model_bundle_path: Optional[str] = None,
) -> Dict[str, Dict[str, float]]:
    if output_path is None:
        output_path = os.path.join("src", "ml-models", "benign_baseline_stats.json")

    if model_bundle_path is None:
        model_bundle_path = settings.MODEL_BUNDLE_PATH

    bundle = joblib.load(model_bundle_path)
    features: List[str] = bundle["features"]

    if data_paths is None:
        candidates = [
            "tests/data/sample_real_flows.csv",
            "tests/data/portscan_slice.csv",
        ]
        data_paths = [p for p in candidates if os.path.exists(p)]

    if not data_paths:
        raise FileNotFoundError("No input dataset files found to generate benign baseline stats.")

    benign_dfs = []
    for path in data_paths:
        df = pd.read_csv(path)
        lbl_col = find_label_col(df)
        mask = df[lbl_col].astype(str).str.strip().str.upper() == "BENIGN"
        b_df = df[mask].copy()
        benign_dfs.append(b_df)
        print(f"Loaded {len(b_df)} benign flows from {path}")

    combined = pd.concat(benign_dfs, ignore_index=True)
    col_map = {c.strip().lower(): c for c in combined.columns}

    stats: Dict[str, Dict[str, float]] = {}

    for feat in features:
        feat_clean = feat.strip().lower()
        if feat_clean not in col_map:
            raise KeyError(f"Feature '{feat}' not present in benign dataset columns")

        raw_col = col_map[feat_clean]
        series = pd.to_numeric(combined[raw_col], errors="coerce").replace([np.inf, -np.inf], np.nan).dropna()

        stats[feat] = {
            "mean": float(np.round(series.mean(), 6)),
            "std": float(np.round(series.std(ddof=0), 6)),
            "p5": float(np.round(series.quantile(0.05), 6)),
            "p25": float(np.round(series.quantile(0.25), 6)),
            "p50": float(np.round(series.quantile(0.50), 6)),
            "p75": float(np.round(series.quantile(0.75), 6)),
            "p95": float(np.round(series.quantile(0.95), 6)),
            "p99": float(np.round(series.quantile(0.99), 6)),
        }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)

    print(f"\nSuccessfully generated benign baseline reference stats for {len(stats)} features across {len(combined)} benign flows.")
    print(f"Exported artifact to: {output_path}")
    return stats


def main():
    parser = argparse.ArgumentParser(description="Generate benign baseline reference stats JSON")
    parser.add_argument("--data", nargs="+", help="CSV files containing benign traffic")
    parser.add_argument("--output", type=str, help="Path to write benign_baseline_stats.json")
    parser.add_argument("--model", type=str, help="Path to packetsage_model.joblib")
    args = parser.parse_args()

    generate_benign_baseline(data_paths=args.data, output_path=args.output, model_bundle_path=args.model)


if __name__ == "__main__":
    main()
