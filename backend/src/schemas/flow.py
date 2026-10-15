from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    upload_id: str = Field(description="Unique identifier for this upload session")
    total_rows: int = Field(description="Total number of rows processed from the CSV")
    valid_rows: int = Field(description="Number of rows with <=20% unusable features")
    invalid_rows: int = Field(description="Number of rows flagged invalid due to >20% unusable features")
    suspicious_rows: int = Field(description="Number of rows whose supervised score met or exceeded threshold")
    unusual_rows: int = Field(description="Number of rows flagged as unusual by the novelty detector")
    warnings: list[str] = Field(default_factory=list, description="Warnings encountered during upload/parsing")
    incident_count: int = Field(default=0, description="Total number of incidents identified through correlation")



class FlowRecord(BaseModel):
    flow_id: int
    upload_id: str
    row_index: int
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    ts: str | None = None
    score: float | None = None
    label: str  # "benign", "suspicious", "invalid"
    unusual: bool = False
    incident_id: str | None = None
