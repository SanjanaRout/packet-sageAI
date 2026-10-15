from fastapi import HTTPException, status

from core.database import mongodb
from services.model_service import ModelService, model_service


def get_db():
    return mongodb.get_db()


def get_model_service() -> ModelService:
    if not model_service.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model service is currently unavailable or not loaded",
        )
    return model_service


