"""
src/services/baseline_service.py

Service for evaluating per-flow statistical deviations against benign training baseline
reference distributions. Explicitly frames deviations as statistical comparisons against
training data quantiles rather than causal explanations or SHAP values.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.config import settings

logger = logging.getLogger("packet_sage")

DISCLAIMER_TEXT = "statistical deviation from benign baseline (not a causal model explanation / SHAP)"


class BaselineService:
    def __init__(self, baseline_path: Optional[str] = None):
        self.baseline_path = baseline_path or settings.BENIGN_BASELINE_PATH
        self._stats: Dict[str, Dict[str, float]] = {}
        self._is_loaded: bool = False

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    def load(self, force: bool = False) -> None:
        if self._is_loaded and not force:
            return

        resolved_path = Path(self.baseline_path)
        if not resolved_path.is_absolute():
            # Try relative to cwd or backend directory
            if not resolved_path.exists():
                candidate = Path(__file__).resolve().parent.parent / "ml-models" / "benign_baseline_stats.json"
                if candidate.exists():
                    resolved_path = candidate

        if not resolved_path.exists():
            logger.warning("Benign baseline stats file not found at %s", resolved_path)
            self._stats = {}
            self._is_loaded = False
            return

        try:
            with open(resolved_path, "r", encoding="utf-8") as f:
                self._stats = json.load(f)
            self._is_loaded = True
            logger.info("Loaded benign baseline stats for %d features from %s", len(self._stats), resolved_path)
        except Exception as exc:
            logger.error("Failed loading benign baseline stats from %s: %s", resolved_path, exc)
            self._stats = {}
            self._is_loaded = False

    @property
    def stats(self) -> Dict[str, Dict[str, float]]:
        if not self._is_loaded:
            self.load()
        return self._stats

    def compute_flow_deviations(
        self,
        features_dict: Dict[str, Any],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Compares numeric feature values against benign baseline quantiles.
        Returns top_k most extreme features (>= p95 or <= p5), with raw value,
        benign median (p50), percentile bracket, and explicit non-causal disclaimer.
        """
        stats = self.stats
        if not stats:
            return []

        # Case-insensitive mapping of input features
        input_lower = {k.strip().lower(): (k, v) for k, v in features_dict.items() if v is not None}

        candidate_deviations: List[Dict[str, Any]] = []

        for feat_name, ref in stats.items():
            feat_lower = feat_name.strip().lower()
            if feat_lower not in input_lower:
                continue

            orig_key, raw_val = input_lower[feat_lower]
            try:
                val = float(raw_val)
            except (ValueError, TypeError):
                continue

            if np.isnan(val) or np.isinf(val):
                continue

            p5 = ref["p5"]
            p25 = ref["p25"]
            p50 = ref["p50"]
            p75 = ref["p75"]
            p95 = ref["p95"]
            p99 = ref["p99"]
            mean = ref["mean"]
            std = ref["std"]

            # Bracket determination
            is_extreme = False
            bracket = "within normal benign range (25th-75th percentile)"
            extremity_weight = 0.0

            if val >= p99 and p99 > p50:
                bracket = ">99th percentile of benign training traffic"
                is_extreme = True
                extremity_weight = 4.0 + (val - p99) / (std + 1e-6)
            elif val >= p95 and p95 > p50:
                bracket = ">95th percentile of benign training traffic"
                is_extreme = True
                extremity_weight = 3.0 + (val - p95) / (std + 1e-6)
            elif val <= p5 and p5 < p50:
                bracket = "<5th percentile of benign training traffic"
                is_extreme = True
                extremity_weight = 3.0 + (p5 - val) / (std + 1e-6)
            elif val > p75 and p75 > p50:
                bracket = ">75th percentile of benign training traffic"
                extremity_weight = 1.0
            elif val < p25 and p25 < p50:
                bracket = "<25th percentile of benign training traffic"
                extremity_weight = 1.0

            z_score = (val - mean) / std if std > 0 else 0.0

            candidate_deviations.append(
                {
                    "feature": feat_name,
                    "value": float(np.round(val, 4)),
                    "benign_median": float(np.round(p50, 4)),
                    "bracket": bracket,
                    "z_score": float(np.round(z_score, 2)),
                    "is_extreme": is_extreme,
                    "extremity_weight": float(extremity_weight),
                    "disclaimer": DISCLAIMER_TEXT,
                }
            )

        # Prioritize extreme features (>= p95 or <= p5), then sort by extremity weight descending
        candidate_deviations.sort(
            key=lambda d: (1 if d["is_extreme"] else 0, d["extremity_weight"], abs(d["z_score"])),
            reverse=True,
        )

        return candidate_deviations[:top_k]

    def format_deviations_text(self, deviations: List[Dict[str, Any]]) -> str:
        if not deviations:
            return "No notable statistical deviations from benign baseline."

        lines = []
        for d in deviations:
            lines.append(
                f"- {d['feature']}: {d['value']} (benign median: {d['benign_median']}, {d['bracket']})"
            )
        lines.append(f"  Note: {DISCLAIMER_TEXT}")
        return "\n".join(lines)


baseline_service = BaselineService()
