from __future__ import annotations

import logging
from fastapi import APIRouter, HTTPException, Query, status

from schemas.incident import IncidentDetailResponse, IncidentResponse
from services.correlation_service import correlation_service

logger = logging.getLogger("packet_sage")

router = APIRouter()


@router.get(
    "/",
    response_model=list[IncidentResponse],
    summary="List flagged incidents",
    description="Retrieve all flagged incidents, optionally filtered by upload_id, ordered by max_score descending.",
)
async def list_incidents(
    upload_id: str | None = Query(default=None, description="Filter incidents by upload_id"),
) -> list[IncidentResponse]:
    incidents = await correlation_service.get_incidents(upload_id=upload_id)
    return incidents


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    summary="Get incident details",
    description="Retrieve a specific flagged incident by ID, including paginated associated suspicious/flagged flows and analyst feedback.",
)
async def get_incident(
    incident_id: str,
    skip: int = Query(default=0, ge=0, description="Number of flow records to skip"),
    limit: int = Query(default=200, ge=1, le=1000, description="Max number of flow records to return"),
) -> IncidentDetailResponse:
    incident = await correlation_service.get_incident_detail(
        incident_id=incident_id, skip=skip, limit=limit
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return incident

