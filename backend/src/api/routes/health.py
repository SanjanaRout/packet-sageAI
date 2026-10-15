from fastapi import APIRouter

from core.config import settings
from core.database import mongodb

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
    }
