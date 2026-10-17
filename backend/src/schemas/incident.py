from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from schemas.flow import FlowRecord


class IncidentResponse(BaseModel):
    incident_id: str
    upload_id: str
    kinds: list[str] = Field(description="Incident categories (e.g. suspicious_burst, port_scan, fan_in)")
    start: str = Field(description="Earliest timestamp in the incident")
    end: str = Field(description="Latest timestamp in the incident")
    flow_count: int = Field(description="Total count of associated flagged flows")
    max_score: float = Field(description="Highest model score across associated flows")
    src_ips: list[str] = Field(default_factory=list, description="Capped list of source IPs")
    dst_ips: list[str] = Field(default_factory=list, description="Capped list of destination IPs")
    reasons: list[str] = Field(default_factory=list, description="Reasons for flagging the incident")
    flow_ids: list[int] = Field(default_factory=list, description="Associated flow IDs")
    status: str = Field(default="open", description="Incident status: open, closed, under_review")
    time_shift_applied: bool = Field(default=False, description="Whether 12-hour clock shift was applied to this upload")
    created_at: str = Field(description="ISO timestamp of incident creation")


class IncidentDetailResponse(IncidentResponse):
    flows: list[FlowRecord] = Field(default_factory=list, description="Associated flow records (paginated)")
    total_flows: int = Field(description="Total flow count for this incident")
    skip: int = Field(default=0, description="Number of skipped flow records")
    limit: int = Field(default=200, description="Maximum number of flow records returned")
    feedback: list[dict[str, Any]] = Field(default_factory=list, description="Analyst feedback history")


class AskIncidentRequest(BaseModel):
    question: str | None = Field(default=None, description="Optional specific investigation question for the assistant")


class AskIncidentResponse(BaseModel):
    answer: str
    cited_flow_ids: list[int]
    invalid_citations: list[int]
    provider: str
    model: str


class FeedbackRequest(BaseModel):
    decision: str = Field(description="Analyst decision: confirmed, incorrect, or inconclusive")
    note: str = Field(default="", description="Analyst observations and rationale")
    notes: str | None = Field(default=None, description="Alias for note")
    analyst_id: str | None = Field(default=None, description="Optional analyst identifier")
    name: str | None = Field(default=None, description="Optional analyst name")
    analyst_name: str | None = Field(default=None, description="Optional analyst name")

    def get_effective_note(self) -> str:
        if self.notes is not None and self.notes != "":
            return self.notes
        return self.note

    def get_effective_analyst_name(self) -> str | None:
        return self.analyst_name or self.name


class FeedbackResponse(BaseModel):
    incident_id: str
    decision: str
    note: str
    timestamp: str
    feedback_count: int
    analyst_id: str | None = None
    analyst_name: str | None = None


class LLMStatusResponse(BaseModel):
    provider: str
    model: str
    base_url_host: str | None = None
    configured: bool


class IsolatedFlowsResponse(BaseModel):
    upload_id: str
    flow_ids: list[int] = Field(default_factory=list, description="Capped list of up to 1000 isolated flow IDs")
    total_count: int = Field(default=0, description="Total count of isolated flagged flows")


class IncidentsWithIsolatedResponse(BaseModel):
    incidents: list[IncidentResponse]
    isolated_flagged_flows: IsolatedFlowsResponse


class ObservedFacts(BaseModel):
    time_window: str = Field(description="Earliest to latest flow timestamp")
    time_shift_applied: bool = Field(description="Whether 12-hour clock shift was applied")
    time_metadata_note: str = Field(description="Clarification on timestamp format and shift assumptions")
    src_ips: list[str] = Field(description="Source IP addresses")
    dst_ips: list[str] = Field(description="Target destination IP addresses")
    dst_ports: list[int] = Field(description="Target destination ports")
    flow_count: int = Field(description="Total flow count for the incident")
    rules_triggered: list[str] = Field(description="Correlation rule categories triggered")
    reasons: list[str] = Field(description="Specific rule trigger descriptions and rationale")
    score_min: float = Field(description="Lowest model score among evidence flows")
    score_max: float = Field(description="Peak anomaly model score")
    top_feature_deviations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Aggregated statistical feature deviations vs. benign baseline",
    )


class SupportingEvidenceFlow(BaseModel):
    flow_id: int
    ts: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    score: float | None = None
    label: str | None = None
    unusual: bool = False
    deviations: list[dict[str, Any]] = Field(default_factory=list)


class AnalystFeedbackEntry(BaseModel):
    decision: str
    note: str
    timestamp: str
    analyst_id: str | None = None
    analyst_name: str | None = None


class AnalystFeedbackHistory(BaseModel):
    current_status: str
    latest_decision: str | None = None
    feedback_entries: list[AnalystFeedbackEntry] = Field(default_factory=list)


class IncidentReportResponse(BaseModel):
    incident_id: str
    upload_id: str
    generated_at: str
    executive_summary: str
    observed_facts: ObservedFacts
    supporting_evidence: list[SupportingEvidenceFlow]
    hypotheses_and_uncertainties: list[str]
    recommended_next_steps: list[str]
    analyst_feedback_history: AnalystFeedbackHistory
    markdown_report: str | None = Field(default=None, description="Rendered markdown version of the investigation report")




