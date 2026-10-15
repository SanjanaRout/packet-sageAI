from fastapi import APIRouter

from core.config import settings
from core.database import mongodb
from services.model_service import model_service

router = APIRouter()


@router.get("/")
async def health_check():
    is_ok, error = await mongodb.ping()
    db_status = "healthy" if is_ok else "unhealthy"

    return {
        "status": "healthy" if is_ok else "degraded",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": {
            "status": db_status,
            "name": settings.MONGODB_DB_NAME,
            **({"detail": error} if error else {}),
        },
        "model": {
            "model_loaded": model_service.is_loaded,
            "status": "loaded" if model_service.is_loaded else "unloaded",
            "features_count": len(model_service.features) if model_service.is_loaded else 0,
            "threshold": model_service.threshold if model_service.is_loaded else None,
            "novelty_threshold": model_service.novelty_threshold if model_service.is_loaded else None,
            "sklearn_version": model_service.sklearn_version if model_service.is_loaded else None,
        },

    }

