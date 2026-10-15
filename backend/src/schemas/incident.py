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
    created_at: str = Field(description="ISO timestamp of incident creation")


class IncidentDetailResponse(IncidentResponse):
    flows: list[FlowRecord] = Field(default_factory=list, description="Associated flow records (paginated)")
    total_flows: int = Field(description="Total flow count for this incident")
    skip: int = Field(default=0, description="Number of skipped flow records")
    limit: int = Field(default=200, description="Maximum number of flow records returned")
    feedback: list[dict[str, Any]] = Field(default_factory=list, description="Analyst feedback history")

