from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
import openai
from google import genai
from google.genai import types

from core.config import settings
from services.llm.base import (
    LLMAuthError,
    LLMConfigError,
    LLMError,
    LLMProvider,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
)

logger = logging.getLogger("llm_service")


def get_active_providers(preferred_provider: Optional[str] = None) -> List[str]:
    raw_order = [p.strip().lower() for p in settings.llm_provider_order.split(",") if p.strip()]

    if preferred_provider:
        pref = preferred_provider.strip().lower()
        if pref in raw_order:
            raw_order.remove(pref)
        raw_order.insert(0, pref)

    provider_keys: Dict[str, str] = {
        "gemini": settings.gemini_api_key,
        "groq": settings.groq_api_key,
        "mistral": settings.mistral_api_key,
    }

    # Also support general LLM_API_KEY if configured
    if settings.LLM_API_KEY and settings.LLM_API_KEY.get_secret_value().strip():
        provider_keys["openai_compat"] = settings.LLM_API_KEY.get_secret_value()
        if "openai_compat" not in raw_order:
            raw_order.append("openai_compat")

    # Localhost / local ollama bypass (no key required for localhost)
    if settings.LLM_BASE_URL and ("localhost" in settings.LLM_BASE_URL or "127.0.0.1" in settings.LLM_BASE_URL):
        provider_keys["openai_compat"] = "ollama-no-key"
        if "openai_compat" not in raw_order:
            raw_order.append("openai_compat")

    providers = []
    for p in raw_order:
        if p in provider_keys and provider_keys[p]:
            providers.append(p)

    return providers


def get_openai_client(provider: str, custom_model: Optional[str] = None) -> Tuple[openai.AsyncOpenAI, str]:
    timeout = settings.LLM_TIMEOUT_SECONDS

    if provider == "groq":
        return openai.AsyncOpenAI(
            api_key=settings.groq_api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=timeout,
        ), custom_model or settings.groq_llm_model
    elif provider == "mistral":
        return openai.AsyncOpenAI(
            api_key=settings.mistral_api_key,
            base_url="https://api.mistral.ai/v1",
            timeout=timeout,
        ), custom_model or settings.mistral_llm_model
    elif provider == "openai_compat":
        key = settings.LLM_API_KEY.get_secret_value() if settings.LLM_API_KEY else "ollama-no-key"
        return openai.AsyncOpenAI(
            api_key=key,
            base_url=settings.LLM_BASE_URL or "https://api.openai.com/v1",
            timeout=timeout,
        ), custom_model or settings.LLM_MODEL
    else:
        raise ValueError(f"Unknown OpenAI-compatible provider: {provider}")


def _sanitize_error(err_str: str) -> str:
    cleaned = str(err_str)
    for key in [settings.gemini_api_key, settings.groq_api_key, settings.mistral_api_key]:
        if key and len(key) > 5:
            cleaned = cleaned.replace(key, "[REDACTED]")
    if settings.LLM_API_KEY:
        k = settings.LLM_API_KEY.get_secret_value()
        if k and len(k) > 5:
            cleaned = cleaned.replace(k, "[REDACTED]")
    return cleaned


def prepare_openai_messages(history: List[Dict[str, str]], query: str, system_instruction: str) -> List[Dict[str, str]]:
    if settings.LLM_SYSTEM_AS_USER:
        full_content = f"{system_instruction}\n\n{query}" if system_instruction and query else (system_instruction or query)
        return [{"role": "user", "content": full_content}]

    messages = []
    if system_instruction:
        messages.append({"role": "system", "content": system_instruction})

    for msg in history:
        role = "assistant" if msg.get("role") in ["model", "assistant"] else "user"
        messages.append({"role": role, "content": msg["content"]})

    if query:
        messages.append({"role": "user", "content": query})

    return messages


async def generate_text_with_fallback(
    prompt: str,
    system_instruction: Optional[str] = None,
    preferred_provider: Optional[str] = None,
    preferred_model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 1000,
) -> Tuple[str, str, str]:
    """
    Generate completion using multi-provider fallback matching repo-assistant.
    Returns (response_text, provider_name, model_name).
    """
    active_providers = get_active_providers(preferred_provider)
    if not active_providers:
        raise LLMConfigError("No LLM providers have active API keys configured.")

    errors: List[str] = []
    auth_errors = 0
    rate_limit_errors = 0
    timeout_errors = 0

    import asyncio

    for provider in active_providers:
        model_info = preferred_model if preferred_model else (
            settings.gemini_llm_model if provider == "gemini" else getattr(settings, f"{provider}_llm_model", settings.LLM_MODEL)
        )
        try:
            if provider == "gemini":
                model_to_use = preferred_model if (preferred_provider == "gemini" and preferred_model) else settings.gemini_llm_model
                print(f"[LLM Processing] Processing text request with provider '{provider}' (model: '{model_to_use}')...")
                logger.info(f"[LLM Processing] Processing text request with provider '{provider}' (model: '{model_to_use}')...")

                client = genai.Client(api_key=settings.gemini_api_key)
                full_prompt = f"{system_instruction}\n\n{prompt}" if system_instruction else prompt
                response = await client.aio.models.generate_content(
                    model=model_to_use,
                    contents=full_prompt,
                )
                print(f"[LLM Success] Request successfully completed by provider '{provider}' (model: '{model_to_use}').")
                text = response.text.strip() if response.text else ""
                return text, provider, model_to_use
            else:
                custom_m = preferred_model if (preferred_provider == provider and preferred_model) else None
                oai_client, model = get_openai_client(provider, custom_m)
                print(f"[LLM Processing] Processing text request with provider '{provider}' (model: '{model}')...")
                logger.info(f"[LLM Processing] Processing text request with provider '{provider}' (model: '{model}')...")

                messages = prepare_openai_messages([], prompt, system_instruction or "")

                kwargs: Dict[str, Any] = {
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                }

                attempt = 0
                while True:
                    try:
                        response = await oai_client.chat.completions.create(**kwargs)
                        break
                    except openai.BadRequestError as bad_req:
                        # Fallback for max_tokens vs max_completion_tokens
                        bad_req_str = str(bad_req).lower()
                        if "max_completion_tokens" in bad_req_str or "max_tokens" in bad_req_str:
                            kwargs.pop("max_tokens", None)
                            kwargs["max_completion_tokens"] = max_tokens
                            response = await oai_client.chat.completions.create(**kwargs)
                            break
                        raise
                    except (openai.RateLimitError, openai.APITimeoutError, openai.APIConnectionError):
                        if attempt < settings.LLM_MAX_RETRIES:
                            attempt += 1
                            await asyncio.sleep(0.5 * (2 ** attempt))
                            continue
                        raise

                content = response.choices[0].message.content
                print(f"[LLM Success] Request successfully completed by provider '{provider}' (model: '{model}').")
                text = content.strip() if content else ""
                return text, provider, model

        except Exception as e:
            sanitized_e = _sanitize_error(str(e))
            print(f"[LLM Fallback Alert] Provider '{provider}' (model: '{model_info}') failed with error: {sanitized_e}. Falling back to next available provider...")
            logger.warning(f"[LLM Fallback Alert] Provider '{provider}' (model: '{model_info}') failed: {sanitized_e}")
            errors.append(f"{provider}: {sanitized_e}")

            if isinstance(e, (openai.AuthenticationError, openai.PermissionDeniedError)):
                auth_errors += 1
            elif isinstance(e, openai.RateLimitError):
                rate_limit_errors += 1
            elif isinstance(e, (openai.APITimeoutError, openai.APIConnectionError)):
                timeout_errors += 1

    print(f"[LLM Error] All active LLM providers failed.")

    if auth_errors == len(active_providers):
        raise LLMAuthError("All active LLM providers failed authentication.")
    elif rate_limit_errors == len(active_providers):
        raise LLMRateLimitError("All active LLM providers rate limited.")
    elif timeout_errors == len(active_providers):
        raise LLMTimeoutError("All active LLM providers timed out.")
    raise LLMProviderError("All active LLM providers failed to complete request.")


class MultiProviderFallback(LLMProvider):
    """
    LLMProvider implementation wrapping the repo-assistant multi-provider fallback.
    """
    def __init__(self, preferred_provider: Optional[str] = None, preferred_model: Optional[str] = None):
        self.preferred_provider = preferred_provider
        self.preferred_model = preferred_model
        self.last_used_provider: Optional[str] = None
        self.last_used_model: Optional[str] = None

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int = 1000,
        temperature: float = 0.2,
    ) -> str:
        text, provider, model = await generate_text_with_fallback(
            prompt=user,
            system_instruction=system,
            preferred_provider=self.preferred_provider,
            preferred_model=self.preferred_model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        self.last_used_provider = provider
        self.last_used_model = model
        return text
