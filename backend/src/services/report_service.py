"""
src/services/report_service.py

Structured Incident Report generation service providing executive summaries,
observed facts, supporting flow evidence, non-causal statistical deviations,
hypotheses & uncertainties, and human-in-the-loop recommended next steps.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from schemas.incident import (
    AnalystFeedbackEntry,
    AnalystFeedbackHistory,
    IncidentReportResponse,
    ObservedFacts,
    SupportingEvidenceFlow,
)
from services.baseline_service import baseline_service
from services.correlation_service import correlation_service
from services.model_service import model_service

logger = logging.getLogger("packet_sage")


class ReportService:
    async def generate_report(
        self,
        incident_id: str,
        generate_llm: bool = False,
    ) -> Optional[IncidentReportResponse]:
        incident = await correlation_service.get_incident_detail(
            incident_id=incident_id, skip=0, limit=50
        )
        if not incident:
            return None

        upload_id = incident.get("upload_id", "unknown")
        kinds = incident.get("kinds", [])
        reasons = incident.get("reasons", [])
        start = str(incident.get("start", "unknown"))
        end = str(incident.get("end", "unknown"))
        flow_count = int(incident.get("flow_count", len(incident.get("flow_ids", []))))
        max_score = float(incident.get("max_score", 0.0))
        time_shift_applied = bool(incident.get("time_shift_applied", False))

        raw_flows = incident.get("flows", [])
        scores = [f["score"] for f in raw_flows if f.get("score") is not None]
        score_min = float(min(scores)) if scores else max_score
        score_max = float(max(scores)) if scores else max_score

        src_ips = sorted(list({f["src_ip"] for f in raw_flows if f.get("src_ip")}))
        if not src_ips:
            src_ips = list(incident.get("src_ips", []))

        dst_ips = sorted(list({f["dst_ip"] for f in raw_flows if f.get("dst_ip")}))
        if not dst_ips:
            dst_ips = list(incident.get("dst_ips", []))

        dst_ports = sorted(list({f["dst_port"] for f in raw_flows if f.get("dst_port") is not None}))

        time_metadata_note = (
            "Source timestamps lack native AM/PM tags. 12-hour business-hours clock shift WAS applied "
            "to this upload (hours 1..7 shifted forward by 12h)."
            if time_shift_applied
            else "Source timestamps lack native AM/PM tags. No 12-hour clock shift was applied."
        )

        # Supporting evidence flows
        supporting_flows: List[SupportingEvidenceFlow] = []
        all_deviations: List[Dict[str, Any]] = []

        for f in raw_flows[:20]:
            devs = f.get("deviations", [])
            if not devs and f.get("features"):
                devs = baseline_service.compute_flow_deviations(f["features"], top_k=3)
            all_deviations.extend(devs)

            supporting_flows.append(
                SupportingEvidenceFlow(
                    flow_id=int(f["flow_id"]),
                    ts=str(f.get("ts")) if f.get("ts") else None,
                    src_ip=str(f.get("src_ip")) if f.get("src_ip") else None,
                    dst_ip=str(f.get("dst_ip")) if f.get("dst_ip") else None,
                    dst_port=int(f["dst_port"]) if f.get("dst_port") is not None else None,
                    score=float(f["score"]) if f.get("score") is not None else None,
                    label=str(f.get("label", "unknown")),
                    unusual=bool(f.get("unusual", False)),
                    deviations=devs,
                )
            )

        # Aggregate top distinct feature deviations
        top_deviations_dict: Dict[str, Dict[str, Any]] = {}
        for d in all_deviations:
            feat = d["feature"]
            if feat not in top_deviations_dict or d.get("extremity_weight", 0) > top_deviations_dict[feat].get("extremity_weight", 0):
                top_deviations_dict[feat] = d

        top_feature_deviations = sorted(
            list(top_deviations_dict.values()),
            key=lambda d: (1 if d.get("is_extreme") else 0, d.get("extremity_weight", 0), abs(d.get("z_score", 0))),
            reverse=True,
        )[:5]

        # Observed Facts
        observed_facts = ObservedFacts(
            time_window=f"{start} to {end}",
            time_shift_applied=time_shift_applied,
            time_metadata_note=time_metadata_note,
            src_ips=src_ips[:10],
            dst_ips=dst_ips[:10],
            dst_ports=dst_ports[:20],
            flow_count=flow_count,
            rules_triggered=kinds,
            reasons=reasons,
            score_min=score_min,
            score_max=score_max,
            top_feature_deviations=top_feature_deviations,
        )

        # Analyst Feedback History
        feedback_raw = incident.get("feedback", [])
        feedback_entries = [
            AnalystFeedbackEntry(
                decision=str(fb.get("decision", "unknown")),
                note=str(fb.get("note", "")),
                timestamp=str(fb.get("timestamp", "")),
            )
            for fb in feedback_raw
        ]
        current_status = str(incident.get("latest_decision") or incident.get("status", "open"))
        analyst_history = AnalystFeedbackHistory(
            current_status=current_status,
            latest_decision=str(incident.get("latest_decision")) if incident.get("latest_decision") else None,
            feedback_entries=feedback_entries,
        )

        # Hypotheses and Uncertainties
        hypotheses: List[str] = []
        if "port_scan" in kinds:
            hypotheses.append(
                f"Horizontal Port Scan: Concentrated connection pattern from {src_ips[:1]} contacting {len(dst_ports)} "
                f"distinct ports within a short tumbling window is characteristic of active network reconnaissance or vulnerability discovery."
            )
            hypotheses.append(
                "Benign Alternative: Network monitoring sweep, authorized security scanner (e.g. Nessus, Qualys), "
                "or client application initiating parallel ephemeral connections."
            )
        if "fan_in" in kinds:
            hypotheses.append(
                f"Distributed Fan-In: Multiple distinct source IPs targeting {dst_ips[:1]} matches distributed denial-of-service (DDoS) "
                "or distributed credential stuffing activity."
            )
            hypotheses.append(
                "Benign Alternative: High-demand public web/API endpoint receiving concurrent legitimate traffic spikes or NTP/DNS queries."
            )
        if "suspicious_burst" in kinds:
            hypotheses.append(
                "Suspicious Burst: High rate of flows exceeded supervised machine learning anomaly threshold."
            )

        # Model & data caveats
        hypotheses.append(
            "Statistical Evidence Disclaimer: Feature deviations represent statistical differences relative to the benign training "
            "baseline distribution (e.g. quantiles >= p95 or <= p5), NOT causal explanations or SHAP attribution values."
        )
        hypotheses.append(
            "Unobserved Factors: Network packet payloads, encrypted TLS handshake details, and endpoint process trees are not "
            "inspected in NetFlow records and must be correlated via external logs."
        )

        # Recommended Next Steps (Human-reviewed, no autonomous blocking)
        next_steps = [
            f"Verify whether source IP(s) {src_ips[:3]} correspond to known internal vulnerability scanners, inventory systems, or authorized automation.",
            f"Review destination server authentication and web server logs on port(s) {dst_ports[:5]} for anomalous HTTP status codes or unauthorized access attempts.",
            "Inspect perimeter firewall and NetFlow session state to determine if TCP handshakes completed (SYN-ACK / ESTABLISHED) or were dropped.",
            "Cross-reference source and destination hosts against Endpoint Detection & Response (EDR) telemetry to inspect originating process binaries.",
            f"Record analyst triage findings (confirmed threat, false positive, or inconclusive) via POST /api/v1/incidents/{incident_id}/feedback.",
        ]

        # Executive Summary
        dev_summary_snippets = [
            f"{d['feature']} ({d['bracket']}, value: {d['value']})"
            for d in top_feature_deviations[:3]
        ]
        dev_text = f" Notable statistical feature deviations: {'; '.join(dev_summary_snippets)}." if dev_summary_snippets else ""

        executive_summary = (
            f"Incident {incident_id} encompasses {flow_count} network flow(s) observed between {start} and {end}, "
            f"triggering correlation rule(s): {', '.join(kinds)}. Activity involved {len(src_ips)} source IP(s) "
            f"({', '.join(src_ips[:3])}) contacting {len(dst_ips)} target IP(s) ({', '.join(dst_ips[:3])}) across "
            f"{len(dst_ports)} destination port(s). Peak anomaly score reached {score_max:.4f} "
            f"(supervised threshold {getattr(model_service, 'threshold', 0.127):.4f}).{dev_text}"
        )

        # Optional LLM Enhancement if requested and provider available
        if generate_llm:
            try:
                from services.assistant_service import assistant_service
                llm_response = await assistant_service.ask_incident(
                    incident,
                    user_question="Summarize the executive summary and hypotheses for the incident report.",
                )
                if llm_response and llm_response.answer:
                    executive_summary += f"\n\n[GenAI Investigation Synthesis ({llm_response.provider} / {llm_response.model})]:\n{llm_response.answer}"
            except Exception as exc:
                logger.warning("Optional LLM report generation failed; fallback to deterministic report: %s", exc)

        return IncidentReportResponse(
            incident_id=incident_id,
            upload_id=upload_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            executive_summary=executive_summary,
            observed_facts=observed_facts,
            supporting_evidence=supporting_flows,
            hypotheses_and_uncertainties=hypotheses,
            recommended_next_steps=next_steps,
            analyst_feedback_history=analyst_history,
        )


report_service = ReportService()
