import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from api.router import api_router
from core.config import settings
from core.database import mongodb
from middleware import add_cors_middleware, LoggingMiddleware, TimingMiddleware

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger("packet_sage")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown hooks."""
    logger.info("Starting %s v%s", settings.APP_NAME, settings.APP_VERSION)
    await mongodb.connect()
    yield
    await mongodb.disconnect()
    logger.info("Shutdown complete")


# ── Application factory ─────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        debug=settings.DEBUG,
        lifespan=lifespan,
    )

    # Middleware (order matters – outermost first)
    add_cors_middleware(app)
    app.add_middleware(TimingMiddleware)
    app.add_middleware(LoggingMiddleware)

    # Routers
    app.include_router(api_router, prefix=settings.API_PREFIX)

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url=f"{settings.API_PREFIX}/health")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
