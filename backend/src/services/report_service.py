"""
src/services/report_service.py

Structured Incident Report generation service providing executive summaries,
observed facts, supporting flow evidence, non-causal statistical deviations,
hypotheses & uncertainties, and human-in-the-loop recommended next steps.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional

from core.database import mongodb
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

        # Determine true distinct port count across the whole incident:
        # 1. Start from preview flows
        true_port_count = len(dst_ports)

        # 2. Extract port count from incident correlation reasons if present (e.g. "contacted 29689 distinct ports")
        for r in reasons:
            m = re.search(r"contacted\s+(\d+)\s+distinct\s+ports", r, re.IGNORECASE)
            if m:
                true_port_count = max(true_port_count, int(m.group(1)))

        # 3. Query distinct ports from MongoDB if flows collection is available
        flow_ids = incident.get("flow_ids", [])
        if mongodb.is_connected and flow_ids and upload_id != "unknown":
            try:
                flows_coll = mongodb.get_collection("flows")
                distinct_ports = await flows_coll.distinct(
                    "dst_port",
                    {"upload_id": upload_id, "flow_id": {"$in": flow_ids}}
                )
                if distinct_ports:
                    true_port_count = max(true_port_count, len(distinct_ports))
            except Exception:
                pass

        # Clean prose representations (no Python list reprs)
        src_ips_str = ", ".join(src_ips[:3]) if src_ips else "Unknown Source"
        dst_ips_str = ", ".join(dst_ips[:3]) if dst_ips else "Unknown Target"
        dst_ports_str = ", ".join(str(p) for p in dst_ports[:5]) if dst_ports else "N/A"

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
                analyst_id=str(fb.get("analyst_id")) if fb.get("analyst_id") else None,
                analyst_name=str(fb.get("analyst_name")) if fb.get("analyst_name") else None,
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
            if len(dst_ips) <= 1:
                scan_type = "Vertical Port Scan"
                scan_desc = (
                    f"Concentrated connection pattern from {src_ips_str} contacting {true_port_count} "
                    f"distinct port(s) on target {dst_ips_str} within a short tumbling window is characteristic "
                    "of active host-level service enumeration or vulnerability discovery."
                )
            elif true_port_count <= 5:
                scan_type = "Horizontal Sweep"
                scan_desc = (
                    f"Connection sweep from {src_ips_str} targeting {len(dst_ips)} destination IP(s) across "
                    f"{true_port_count} port(s) ({dst_ports_str}) is characteristic of broad network reconnaissance "
                    "seeking specific open services across subnets."
                )
            else:
                scan_type = "Hybrid / Multi-Target Port Scan"
                scan_desc = (
                    f"Broad connection pattern from {src_ips_str} targeting {len(dst_ips)} destination IP(s) across "
                    f"{true_port_count} distinct ports is characteristic of comprehensive network mapping."
                )
            hypotheses.append(f"{scan_type}: {scan_desc}")
            hypotheses.append(
                "Benign Alternative: Network monitoring sweep, authorized security scanner (e.g. Nessus, Qualys), "
                "or client application initiating parallel ephemeral connections."
            )
        if "fan_in" in kinds:
            hypotheses.append(
                f"Distributed Fan-In: Multiple distinct source IPs targeting {dst_ips_str} matches distributed denial-of-service (DDoS) "
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
            f"Verify whether source IP(s) {src_ips_str} correspond to known internal vulnerability scanners, inventory systems, or authorized automation.",
            f"Review destination server authentication and web server logs on port(s) {dst_ports_str} for anomalous HTTP status codes or unauthorized access attempts.",
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
            f"({src_ips_str}) contacting {len(dst_ips)} target IP(s) ({dst_ips_str}) across "
            f"{true_port_count} destination port(s). Peak anomaly score reached {score_max:.4f} "
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

        gen_time = datetime.now(timezone.utc).isoformat()
        markdown_text = self.render_markdown_report(
            incident_id=incident_id,
            upload_id=upload_id,
            generated_at=gen_time,
            executive_summary=executive_summary,
            observed_facts=observed_facts,
            supporting_evidence=supporting_flows,
            hypotheses_and_uncertainties=hypotheses,
            recommended_next_steps=next_steps,
            analyst_feedback_history=analyst_history,
        )

        return IncidentReportResponse(
            incident_id=incident_id,
            upload_id=upload_id,
            generated_at=gen_time,
            executive_summary=executive_summary,
            observed_facts=observed_facts,
            supporting_evidence=supporting_flows,
            hypotheses_and_uncertainties=hypotheses,
            recommended_next_steps=next_steps,
            analyst_feedback_history=analyst_history,
            markdown_report=markdown_text,
        )

    def render_markdown_report(
        self,
        incident_id: str,
        upload_id: str,
        generated_at: str,
        executive_summary: str,
        observed_facts: ObservedFacts,
        supporting_evidence: List[SupportingEvidenceFlow],
        hypotheses_and_uncertainties: List[str],
        recommended_next_steps: List[str],
        analyst_feedback_history: AnalystFeedbackHistory,
    ) -> str:
        md = []
        md.append(f"# Incident Investigation Report: `{incident_id}`\n")
        md.append(f"- **Upload ID:** `{upload_id}`")
        md.append(f"- **Generated At:** {generated_at}")
        md.append(f"- **Current Status:** `{analyst_feedback_history.current_status}`")
        if analyst_feedback_history.latest_decision:
            md.append(f"- **Latest Decision:** `{analyst_feedback_history.latest_decision}`")
        md.append(f"- **Time Window:** {observed_facts.time_window}")
        md.append(f"- **Rules Triggered:** {', '.join(observed_facts.rules_triggered)}")
        md.append(f"- **Clock Shift Applied:** {'Yes' if observed_facts.time_shift_applied else 'No'}")
        md.append(f"- **Time Metadata Note:** {observed_facts.time_metadata_note}\n")

        md.append("## 1. Executive Summary\n")
        md.append(f"{executive_summary}\n")

        md.append("## 2. Observed Facts\n")
        md.append(f"- **Source IPs ({len(observed_facts.src_ips)}):** {', '.join(observed_facts.src_ips) or 'N/A'}")
        md.append(f"- **Target Destination IPs ({len(observed_facts.dst_ips)}):** {', '.join(observed_facts.dst_ips) or 'N/A'}")
        md.append(f"- **Sample Destination Ports:** {', '.join(str(p) for p in observed_facts.dst_ports) or 'N/A'}")
        md.append(f"- **Total Flow Count:** {observed_facts.flow_count}")
        md.append(f"- **Score Range:** {observed_facts.score_min:.4f} to {observed_facts.score_max:.4f}")
        md.append("- **Trigger Reasons:**")
        for r in observed_facts.reasons:
            md.append(f"  - {r}")

        if observed_facts.top_feature_deviations:
            md.append("\n### Top Statistical Feature Deviations vs. Benign Baseline")
            md.append("| Feature | Observed Value | Benign Median (p50) | Percentile Bracket |")
            md.append("| :--- | :--- | :--- | :--- |")
            for dev in observed_facts.top_feature_deviations:
                md.append(f"| `{dev['feature']}` | {dev['value']} | {dev['benign_median']} | {dev['bracket']} |")
            md.append("\n> **Notice:** *Statistical deviations represent differences from the benign training distribution, not causal explanations or SHAP attributions.*\n")

        md.append("## 3. Supporting Evidence Flows\n")
        if supporting_evidence:
            md.append("| Flow ID | Timestamp | Source IP | Destination IP:Port | Score | Label | Unusual | Top Behavioral Deviations |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for f in supporting_evidence[:20]:
                dev_snips = "; ".join(f"{d['feature']}={d['value']} ({d['bracket']})" for d in f.deviations[:2]) if f.deviations else "None"
                dst_port_str = str(f.dst_port) if f.dst_port is not None else "N/A"
                score_str = f"{f.score:.4f}" if f.score is not None else "N/A"
                md.append(f"| `{f.flow_id}` | {f.ts or 'N/A'} | `{f.src_ip or 'N/A'}` | `{f.dst_ip or 'N/A'}:{dst_port_str}` | {score_str} | {f.label or 'N/A'} | {'Yes' if f.unusual else 'No'} | {dev_snips} |")
            md.append("")
        else:
            md.append("No supporting flows available.\n")

        md.append("## 4. Hypotheses & Uncertainties\n")
        for h in hypotheses_and_uncertainties:
            md.append(f"- {h}")
        md.append("")

        md.append("## 5. Recommended Next Steps\n")
        md.append("> **Operational Guidance:** Actions below are analyst-reviewed advisory steps. Autonomous blocking is not performed.\n")
        for idx, step in enumerate(recommended_next_steps, 1):
            md.append(f"{idx}. {step}")
        md.append("")

        md.append("## 6. Analyst Feedback History\n")
        md.append(f"- **Current Status:** `{analyst_feedback_history.current_status}`")
        md.append(f"- **Latest Decision:** `{analyst_feedback_history.latest_decision or 'None'}`\n")
        if analyst_feedback_history.feedback_entries:
            md.append("| Timestamp | Decision | Analyst | Notes |")
            md.append("| :--- | :--- | :--- | :--- |")
            for fb in analyst_feedback_history.feedback_entries:
                analyst = fb.analyst_name or fb.analyst_id or "Unspecified"
                md.append(f"| {fb.timestamp} | `{fb.decision}` | {analyst} | {fb.note} |")
            md.append("")
        else:
            md.append("No analyst feedback recorded yet.\n")

        return "\n".join(md)


report_service = ReportService()
