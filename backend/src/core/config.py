from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


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
    MAX_UPLOAD_SIZE_MB: int = 100
    CHUNK_SIZE_ROWS: int = 100_000
    DB_BATCH_SIZE: int = 5_000
    UPLOAD_DIR: str = "uploads"
    TIMESTAMP_FORMAT: str = "%d/%m/%Y %H:%M:%S"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}





settings = Settings()
