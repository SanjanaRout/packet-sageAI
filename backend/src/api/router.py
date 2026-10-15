from fastapi import APIRouter

from api.routes import health, flows, incidents, llm

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(flows.router, prefix="/flows", tags=["Flows"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(llm.router, prefix="/llm", tags=["LLM"])



