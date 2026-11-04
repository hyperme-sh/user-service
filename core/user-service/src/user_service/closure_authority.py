"""Private closure HTTP authority; deliberately separate from the public app."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx
from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_identity.account_lifecycle import enforcement_enabled
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from user_service.closure_actions import router as actions_router
from user_service.closure_idp import KeycloakClosureClient
from user_service.closure_worker import WorkerUnavailable, check_database, database_url
from user_service.lifecycle_read import require_reader
from user_service.lifecycle_read import router as read_router
from user_service.middleware import UserServiceDbMiddleware


def create_app():
    @asynccontextmanager
    async def lifespan(app):
        if (os.environ.get("ACCOUNT_CLOSURE_AUTHORITY_ENABLED", "").lower() != "true"
                or not enforcement_enabled()):
            raise WorkerUnavailable()
        engine = None
        try:
            engine = create_async_engine(database_url(), pool_pre_ping=True, echo=False)
            await check_database(engine)
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False, timeout=3) as client:
                app.state.closure_directory = KeycloakClosureClient(client)
                maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
                app.state.session_maker = maker
                app.state.closure_session_maker = maker
                yield
        except Exception:  # noqa: BLE001 - sanitize private startup and shutdown diagnostics
            raise WorkerUnavailable() from None
        finally:
            if engine is not None:
                await engine.dispose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(UserServiceDbMiddleware)
    app.include_router(actions_router, prefix="/api/v1")
    app.include_router(read_router, prefix="/api/v1")

    @app.middleware("http")
    async def unavailable(request: Request, call_next):
        # Catch inside ServerErrorMiddleware so Uvicorn cannot log raw SQL,
        # native subjects or provider diagnostics from an operational failure.
        try:
            return await call_next(request)
        except Exception:  # noqa: BLE001 - opaque, retryable private boundary failure
            return JSONResponse(status_code=503, content={"detail": "Private account closure authority unavailable"},
                                headers={"Cache-Control": "no-store"})

    @app.get("/internal/ready", dependencies=[Depends(require_reader)])
    async def ready():
        try:
            await check_database(app.state.session_maker.kw["bind"])
        except Exception:  # noqa: BLE001 - health responses never expose database errors
            raise HTTPException(503, "Private account closure authority unavailable") from None
        return {"ready": True}

    @app.exception_handler(UnauthorizedException)
    async def unauthorized(request: Request, error: UnauthorizedException):
        return JSONResponse(status_code=401, content={"error": "Native account token required"},
                            headers={"Cache-Control": "no-store"})

    @app.exception_handler(ForbiddenException)
    async def forbidden(request: Request, error: ForbiddenException):
        return JSONResponse(status_code=403, content={"error": "Native account permission required"},
                            headers={"Cache-Control": "no-store"})

    return app


app = create_app()
