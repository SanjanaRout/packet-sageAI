from fastapi import APIRouter

from api.routes import health, flows, incidents, llm, model
from api.routes.flows import get_upload_summary
from schemas.flow import UploadResponse

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["Health"])
api_router.include_router(flows.router, prefix="/flows", tags=["Flows"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(llm.router, prefix="/llm", tags=["LLM"])
api_router.include_router(model.router, prefix="/model", tags=["Model"])

# Top-level /uploads/{upload_id} convenience route
api_router.add_api_route(
    "/uploads/{upload_id}",
    get_upload_summary,
    methods=["GET"],
    response_model=UploadResponse,
    tags=["Flows"],
    summary="Get upload summary",
)




