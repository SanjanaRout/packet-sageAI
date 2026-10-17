from __future__ import annotations

import logging
from typing import Any, Union
from fastapi import APIRouter, HTTPException, Query, Response, status

from schemas.incident import (
    AskIncidentRequest,
    AskIncidentResponse,
    FeedbackRequest,
    FeedbackResponse,
    IncidentDetailResponse,
    IncidentReportResponse,
    IncidentResponse,
    IncidentsWithIsolatedResponse,
    IsolatedFlowsResponse,
)

from services.correlation_service import correlation_service


logger = logging.getLogger("packet_sage")

router = APIRouter()


@router.get(
    "/",
    response_model=Union[list[IncidentResponse], IncidentsWithIsolatedResponse],
    summary="List flagged incidents",
    description="Retrieve all flagged incidents, optionally filtered by upload_id, ordered by max_score descending.",
)
async def list_incidents(
    upload_id: str | None = Query(default=None, description="Filter incidents by upload_id"),
    include_isolated: bool = Query(default=False, description="Include isolated_flagged_flows metadata in response"),
    response: Response = None,
) -> Any:
    incidents = await correlation_service.get_incidents(upload_id=upload_id)
    if upload_id:
        iso = await correlation_service.get_isolated_flows(upload_id=upload_id)
        if response:
            response.headers["X-Isolated-Flow-Count"] = str(iso.get("total_count", 0))
        if include_isolated:
            return {"incidents": incidents, "isolated_flagged_flows": iso}
    return incidents


@router.get(
    "/isolated",
    response_model=IsolatedFlowsResponse,
    summary="Get isolated flagged flows for upload",
    description="Retrieve isolated flagged flows (burst size <= ISOLATED_FLOW_MAX) capped at 1000 with total count.",
)
async def get_isolated_flows(
    upload_id: str = Query(description="Filter isolated flagged flows by upload_id"),
) -> IsolatedFlowsResponse:
    return await correlation_service.get_isolated_flows(upload_id=upload_id)


@router.get(
    "/isolated-flows",
    response_model=IsolatedFlowsResponse,
    summary="Get isolated flagged flows for upload",
    description="Retrieve isolated flagged flows (burst size <= ISOLATED_FLOW_MAX) capped at 1000 with total count.",
)
async def get_isolated_flows_alias(
    upload_id: str = Query(description="Filter isolated flagged flows by upload_id"),
) -> IsolatedFlowsResponse:
    return await correlation_service.get_isolated_flows(upload_id=upload_id)



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


@router.get(
    "/{incident_id}/report",
    response_model=IncidentReportResponse,
    summary="Get structured incident report",
    description="Generate a structured incident report containing executive summary, observed facts, statistical feature deviations vs. benign baseline, hypotheses and uncertainties, human-in-the-loop next steps, and analyst feedback.",
)
@router.post(
    "/{incident_id}/report",
    response_model=IncidentReportResponse,
    summary="Generate structured incident report",
    description="Generate a structured incident report containing executive summary, observed facts, statistical feature deviations vs. benign baseline, hypotheses and uncertainties, human-in-the-loop next steps, and analyst feedback.",
)
async def get_incident_report(
    incident_id: str,
    generate_llm: bool = Query(default=False, description="Optionally enrich report with LLM synthesis"),
) -> IncidentReportResponse:
    from services.report_service import report_service

    report = await report_service.generate_report(
        incident_id=incident_id, generate_llm=generate_llm
    )
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return report



@router.post(
    "/{incident_id}/ask",
    response_model=AskIncidentResponse,
    summary="Ask GenAI assistant about incident",
    description="Synthesize evidence-only investigation summary with strict flow ID citations.",
)
async def ask_incident(
    incident_id: str,
    request: AskIncidentRequest = AskIncidentRequest(),
) -> AskIncidentResponse:
    from services.assistant_service import assistant_service
    from services.llm.base import (
        LLMAuthError,
        LLMConfigError,
        LLMProviderError,
        LLMRateLimitError,
        LLMTimeoutError,
    )

    incident = await correlation_service.get_incident_detail(incident_id=incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    try:
        return await assistant_service.ask_incident(incident, request.question)
    except LLMConfigError as err:
        logger.error("LLM configuration error: %s", err)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM assistant is not configured or credentials are missing.",
        ) from None
    except LLMAuthError as err:
        logger.error("LLM authentication failure: %s", err)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LLM provider authentication failed. Check credentials.",
        ) from None
    except LLMRateLimitError as err:
        logger.warning("LLM rate limit: %s", err)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="LLM provider rate limit exceeded. Please retry later.",
        ) from None
    except LLMTimeoutError as err:
        logger.warning("LLM timeout: %s", err)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="LLM provider timed out.",
        ) from None
    except LLMProviderError as err:
        logger.error("LLM provider error: %s", err)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LLM provider error encountered.",
        ) from None
    except Exception as exc:
        logger.error("Unexpected error in assistant endpoint: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="An unexpected error occurred while communicating with the assistant.",
        ) from None


@router.post(
    "/{incident_id}/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record analyst decision feedback",
    description="Record append-only analyst decision (confirmed, incorrect, inconclusive) with notes.",
)
async def record_feedback(
    incident_id: str,
    request: FeedbackRequest,
) -> FeedbackResponse:
    valid_decisions = {"confirmed", "incorrect", "inconclusive"}
    decision = request.decision.lower().strip()
    if decision not in valid_decisions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid decision '{request.decision}'. Expected one of {sorted(valid_decisions)}.",
        )

    res = await correlation_service.add_feedback(
        incident_id=incident_id,
        decision=decision,
        note=request.note,
    )
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return FeedbackResponse(**res)


