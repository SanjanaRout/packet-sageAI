from __future__ import annotations

import logging
from typing import Optional

from core.config import settings
from services.llm.anthropic_provider import AnthropicProvider
from services.llm.base import LLMConfigError, LLMProvider
from services.llm.openai_compat import OpenAICompatProvider

logger = logging.getLogger("packet_sage")

_cached_provider: Optional[LLMProvider] = None


def get_llm_provider(refresh: bool = False) -> LLMProvider:
    global _cached_provider
    if _cached_provider is not None and not refresh:
        return _cached_provider

    provider_name = (settings.LLM_PROVIDER or "openai_compat").lower()
    api_key = settings.LLM_API_KEY.get_secret_value() if settings.LLM_API_KEY else None

    if provider_name == "anthropic":
        provider = AnthropicProvider(
            api_key=api_key,
            model=settings.LLM_MODEL,
            timeout=settings.LLM_TIMEOUT_SECONDS,
            max_retries=settings.LLM_MAX_RETRIES,
            system_as_user=settings.LLM_SYSTEM_AS_USER,
        )
    elif provider_name == "openai_compat":
        provider = OpenAICompatProvider(
            api_key=api_key,
            model=settings.LLM_MODEL,
            base_url=settings.LLM_BASE_URL,
            timeout=settings.LLM_TIMEOUT_SECONDS,
            max_retries=settings.LLM_MAX_RETRIES,
            system_as_user=settings.LLM_SYSTEM_AS_USER,
        )
    else:
        raise LLMConfigError(f"Unsupported LLM_PROVIDER '{settings.LLM_PROVIDER}'. Expected 'openai_compat' or 'anthropic'.")

    _cached_provider = provider
    return _cached_provider
