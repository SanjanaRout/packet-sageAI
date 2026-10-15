import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class TimingMiddleware(BaseHTTPMiddleware):
    """Add an X-Process-Time header to every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response: Response = await call_next(request)
        response.headers["X-Process-Time"] = f"{(time.perf_counter() - start) * 1000:.2f}ms"
        return response
