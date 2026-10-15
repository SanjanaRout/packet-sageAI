from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status

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
    model_service: ModelService = Depends(get_model_service),
) -> UploadResponse:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV file (.csv)",
        )

    return await flow_service.process_upload(file=file, model_service=model_service)
