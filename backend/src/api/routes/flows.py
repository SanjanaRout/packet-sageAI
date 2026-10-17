from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status

from dependencies import get_model_service
from schemas.flow import UploadResponse
from services.flow_service import flow_service
from services.model_service import ModelService

logger = logging.getLogger("packet_sage")

router = APIRouter()


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and score network flows CSV",
    description=(
        "Upload a network flow CSV file for scoring. "
        "Validates required features, streams with size limits, "
        "scores flows with supervised & novelty models in a threadpool, "
        "and batch-inserts flow records."
    ),
)
async def upload_flows(
    file: UploadFile = File(...),
    assume_pm_business_hours: bool | None = Query(default=None, description="Assume 12-hour PM clock for business hours 1..7"),
    assume_pm_business_hours_form: bool | None = Form(default=None, alias="assume_pm_business_hours"),
    model_service: ModelService = Depends(get_model_service),
) -> UploadResponse:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV file (.csv)",
        )

    effective_shift = (
        assume_pm_business_hours
        if assume_pm_business_hours is not None
        else assume_pm_business_hours_form
    )

    return await flow_service.process_upload(
        file=file,
        model_service=model_service,
        assume_pm_business_hours=effective_shift,
    )


@router.get(
    "/uploads/{upload_id}",
    response_model=UploadResponse,
    summary="Get upload summary",
    description="Retrieve upload metadata, record validity counts, and sanitation metrics.",
)
async def get_upload_summary(upload_id: str) -> UploadResponse:
    doc = await flow_service.get_upload_summary(upload_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upload '{upload_id}' not found",
        )
    return UploadResponse(**doc)


