from __future__ import annotations

import asyncio
import logging
from typing import Any

import anthropic
from anthropic import AsyncAnthropic

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


class AnthropicProvider(LLMProvider):
    def __init__(
        self,
        api_key: str | None,
        model: str,
        timeout: float = 60.0,
        max_retries: int = 2,
        system_as_user: bool = False,
    ) -> None:
        key_str = (api_key or "").strip()
        if not key_str:
            raise LLMConfigError("LLM_API_KEY is required when using the Anthropic provider.")

        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.system_as_user = system_as_user
        self.client = AsyncAnthropic(api_key=key_str, timeout=timeout)

    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        temperature: float,
    ) -> str:
        if self.system_as_user:
            user_content = f"{system}\n\n{user}"
            system_param = None
        else:
            user_content = user
            system_param = system

        messages = [{"role": "user", "content": user_content}]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_param:
            kwargs["system"] = system_param

        attempt = 0
        while True:
            try:
                resp = await self.client.messages.create(**kwargs)
                text_blocks = [b.text for b in resp.content if hasattr(b, "text")]
                return "".join(text_blocks)
            except (anthropic.AuthenticationError, anthropic.PermissionDeniedError):
                raise LLMAuthError("Authentication failure with Anthropic. Check API key.") from None
            except anthropic.RateLimitError:
                if attempt < self.max_retries:
                    attempt += 1
                    backoff = (2 ** attempt) * 0.5
                    logger.warning("Anthropic rate limit encountered; retrying in %.2fs (attempt %d/%d)", backoff, attempt, self.max_retries)
                    await asyncio.sleep(backoff)
                    continue
                raise LLMRateLimitError("Anthropic rate limit exceeded.") from None
            except (anthropic.APITimeoutError, anthropic.APIConnectionError):
                if attempt < self.max_retries:
                    attempt += 1
                    backoff = (2 ** attempt) * 0.5
                    logger.warning("Anthropic timeout/connection error; retrying in %.2fs (attempt %d/%d)", backoff, attempt, self.max_retries)
                    await asyncio.sleep(backoff)
                    continue
                raise LLMTimeoutError("Anthropic request timed out or connection failed.") from None
            except anthropic.APIStatusError as exc:
                raise LLMProviderError(f"Anthropic returned status error: {exc.status_code}") from None
            except Exception as exc:
                if isinstance(exc, LLMError):
                    raise
                raise LLMProviderError("Unexpected error communicating with Anthropic.") from None
