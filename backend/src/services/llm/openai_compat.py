from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlparse

import openai
from openai import AsyncOpenAI

from services.llm.base import (
    LLMAuthError,
    LLMConfigError,
    LLMError,
    LLMProvider,
    LLMProviderError,
    LLMRateLimitError,
    LLMTimeoutError,
)

logger = logging.getLogger("packet_sage")


def _is_local_host(url: str | None) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        return hostname in ("localhost", "127.0.0.1", "::1")
    except Exception:
        return False


class OpenAICompatProvider(LLMProvider):
    def __init__(
        self,
        api_key: str | None,
        model: str,
        base_url: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 2,
        system_as_user: bool = False,
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.system_as_user = system_as_user

        # Validation: Allow empty key only for localhost / local servers
        key_str = (api_key or "").strip()
        if not key_str:
            if not _is_local_host(base_url):
                raise LLMConfigError(
                    "LLM_API_KEY is required when using a remote provider. "
                    "Empty API key is only permitted for local servers (localhost/127.0.0.1)."
                )
            key_str = "ollama-no-key"  # SDK expects a non-empty string

        self.client = AsyncOpenAI(
            api_key=key_str,
            base_url=base_url,
            timeout=timeout,
        )

    def _build_messages(self, system: str, user: str) -> list[dict[str, str]]:
        if self.system_as_user:
            return [{"role": "user", "content": f"{system}\n\n{user}"}]
        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    async def _call_api_with_fallback(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
        temperature: float,
    ) -> str:
        # First attempt: standard max_tokens + temperature
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        try:
            resp = await self.client.chat.completions.create(**kwargs)
            return resp.choices[0].message.content or ""
        except openai.BadRequestError as err:
            err_msg = str(err).lower()
            # Fallback 1: Model rejects max_tokens and requires max_completion_tokens (e.g. o1/o3/newer models)
            if "max_completion_tokens" in err_msg or "max_tokens" in err_msg:
                logger.warning(
                    "OpenAI-compatible model %s rejected 'max_tokens'; retrying once with 'max_completion_tokens'",
                    self.model,
                )
                kwargs.pop("max_tokens", None)
                kwargs["max_completion_tokens"] = max_tokens
                # Also drop temperature if model rejects non-1.0 temperature
                if "temperature" in err_msg:
                    kwargs.pop("temperature", None)
                resp = await self.client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content or ""

            # Fallback 2: Model rejects temperature
            if "temperature" in err_msg:
                logger.warning(
                    "OpenAI-compatible model %s rejected 'temperature'; retrying once without temperature",
                    self.model,
                )
                kwargs.pop("temperature", None)
                resp = await self.client.chat.completions.create(**kwargs)
                return resp.choices[0].message.content or ""

            raise

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        temperature: float,
    ) -> str:
        messages = self._build_messages(system, user)
        attempt = 0

        while True:
            try:
                return await self._call_api_with_fallback(messages, max_tokens, temperature)
            except (openai.AuthenticationError, openai.PermissionDeniedError) as exc:
                raise LLMAuthError("Authentication failure with LLM provider. Check API key.") from None
            except openai.RateLimitError as exc:
                if attempt < self.max_retries:
                    attempt += 1
                    backoff = (2 ** attempt) * 0.5
                    logger.warning("LLM rate limit encountered; retrying in %.2fs (attempt %d/%d)", backoff, attempt, self.max_retries)
                    await asyncio.sleep(backoff)
                    continue
                raise LLMRateLimitError("LLM provider rate limit exceeded.") from None
            except (openai.APITimeoutError, openai.APIConnectionError) as exc:
                if attempt < self.max_retries:
                    attempt += 1
                    backoff = (2 ** attempt) * 0.5
                    logger.warning("LLM timeout/connection error; retrying in %.2fs (attempt %d/%d)", backoff, attempt, self.max_retries)
                    await asyncio.sleep(backoff)
                    continue
                raise LLMTimeoutError("LLM provider request timed out or connection failed.") from None
            except openai.APIStatusError as exc:
                raise LLMProviderError(f"LLM provider returned status error: {exc.status_code}") from None
            except Exception as exc:
                if isinstance(exc, LLMError):
                    raise
                raise LLMProviderError("Unexpected error communicating with LLM provider.") from None
