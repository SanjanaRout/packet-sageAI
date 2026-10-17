from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class Settings(BaseSettings):
    APP_NAME: str = "PacketSage AI"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api/v1"

    MONGODB_URL: str = Field(default="mongodb://localhost:27017")
    MONGODB_DB_NAME: str = "packet_sage"

    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    CORS_ORIGINS: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    MODEL_BUNDLE_PATH: str = "src/ml-models/packetsage_model.joblib"
    BENIGN_BASELINE_PATH: str = "src/ml-models/benign_baseline_stats.json"
    MAX_UPLOAD_SIZE_MB: int = 100
    CHUNK_SIZE_ROWS: int = 100_000
    DB_BATCH_SIZE: int = 5_000
    UPLOAD_DIR: str = "uploads"
    ASSUME_NO_AMPM_BUSINESS_HOURS: bool = False
    AMPM_PM_HOURS_START: int = 1
    AMPM_PM_HOURS_END: int = 7

    # Correlation rule parameters
    SCAN_MIN_PORTS: int = 20
    SCAN_MAX_DST_PORT: int | None = 32768
    MIN_BURST_FLOWS: int = 1
    ISOLATED_FLOW_MAX: int = 2


    # GenAI / LLM Settings (matching repo-assistant multi-provider fallback)
    gemini_api_key: str = ""
    gemini_llm_model: str = "gemini-3.1-flash-lite"

    groq_api_key: str = ""
    groq_llm_model: str = "llama-3.3-70b-versatile"

    mistral_api_key: str = ""
    mistral_llm_model: str = "mistral-small-latest"

    # Fallback order of providers (comma separated)
    llm_provider_order: str = "gemini,groq,mistral"

    # Optional custom provider / localhost overrides
    LLM_PROVIDER: str = ""
    LLM_API_KEY: SecretStr | None = None
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_BASE_URL: str | None = None
    LLM_TIMEOUT_SECONDS: float = 60.0
    LLM_MAX_TOKENS: int = 1000
    LLM_TEMPERATURE: float = 0.2
    LLM_MAX_RETRIES: int = 2
    LLM_SYSTEM_AS_USER: bool = False

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}






settings = Settings()
