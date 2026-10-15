from __future__ import annotations

import logging
from fastapi import APIRouter

from schemas.incident import LLMStatusResponse
from services.assistant_service import assistant_service

logger = logging.getLogger("packet_sage")

router = APIRouter()


@router.get(
    "/status",
    response_model=LLMStatusResponse,
    summary="Get LLM configuration status",
    description="Returns current LLM provider, model, base URL host, and whether the provider is configured. Never exposes API keys.",
)
async def get_llm_status() -> LLMStatusResponse:
    return assistant_service.get_status()
