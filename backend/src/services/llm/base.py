from __future__ import annotations

from abc import ABC, abstractmethod


class LLMError(Exception):
    """Base exception for all LLM operations."""
    pass


class LLMConfigError(LLMError):
    """Raised when configuration or credentials are missing or invalid."""
    pass


class LLMAuthError(LLMError):
    """Raised when provider returns an authentication or authorization error (e.g. 401, 403)."""
    pass


class LLMRateLimitError(LLMError):
    """Raised when provider returns a rate limit or quota exceeded error (429)."""
    pass


class LLMTimeoutError(LLMError):
    """Raised when provider request times out."""
    pass


class LLMProviderError(LLMError):
    """Raised on provider server error (5xx) or unrecoverable API error."""
    pass


class LLMProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        system: str,
        user: str,
        *,
        max_tokens: int,
        temperature: float,
    ) -> str:
        """
        Generate completion text given system and user prompts.
        Must be plain text in, plain text out without provider-specific parameters.
        """
        pass
