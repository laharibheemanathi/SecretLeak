"""SecretLeak FastAPI application.

Security posture:

* Binds to 127.0.0.1 by default (see __main__ and the README).
* CORS allows only the explicit local frontend origins — never a wildcard.
* A request-size middleware rejects oversized bodies with 413.
* Exception handlers return generic messages; stack traces are logged locally,
  never sent to the client, and request bodies are never logged.
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .api import api_router
from .core.config import APP_NAME, get_cors_origins, get_max_request_mb
from .core.logging_config import configure_logging, get_logger
from .database import db
from .services.scan_service import ScanError
from .services.settings_service import SettingsError

logger = get_logger(__name__)


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(
        title=f"{APP_NAME} API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),  # explicit local origins only
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.middleware("http")
    async def request_limits(request: Request, call_next):
        # Reject oversized requests before any parsing work happens.
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            limit = get_max_request_mb() * 1024 * 1024
            if int(content_length) > limit:
                return JSONResponse(
                    status_code=413,
                    content={"detail": {
                        "code": "request_too_large",
                        "message": f"Request body exceeds the {get_max_request_mb()} MB limit.",
                    }},
                )
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # Never echo submitted content back (pasted code may contain secrets).
        problems = [
            {"field": ".".join(str(part) for part in err.get("loc", []) if part != "body"),
             "message": err.get("msg", "invalid value")}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content={"detail": {"code": "validation_error",
                                "message": "Request validation failed.",
                                "errors": problems}},
        )

    @app.exception_handler(ScanError)
    async def scan_error_handler(request: Request, exc: ScanError):
        return JSONResponse(
            status_code=400,
            content={"detail": {"code": "scan_error", "message": str(exc)}},
        )

    @app.exception_handler(SettingsError)
    async def settings_error_handler(request: Request, exc: SettingsError):
        return JSONResponse(
            status_code=422,
            content={"detail": {"code": "settings_error", "message": str(exc)}},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": {"code": "http_error", "message": str(exc.detail)}},
        )

    @app.exception_handler(Exception)
    async def generic_handler(request: Request, exc: Exception):
        # Log locally with a request id; send the client a generic message only.
        request_id = uuid.uuid4().hex[:12]
        logger.exception("Unhandled error %s on %s %s", request_id, request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": {
                "code": "internal_error",
                "message": f"Internal server error (reference: {request_id}).",
            }},
        )

    @app.on_event("startup")
    def startup() -> None:
        db.init_db()
        logger.info("%s API started (local mode)", APP_NAME)

    app.include_router(api_router, prefix="/api")
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    # Local-only binding by default.
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, log_level="info")
