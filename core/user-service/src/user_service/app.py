from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from controlplane_api.exceptions import ForbiddenException, UnauthorizedException
from controlplane_api.logging import configure_logging
from controlplane_api.utils import get_logger
from controlplane_api.config import settings
from api.infrastructure.messaging.tenant_event_publisher import (
    install_tenant_event_publisher,
    set_tenant_event_publisher,
    shutdown_tenant_event_publisher,
)
from api.infrastructure.persistence.db_session import configure_session_maker
from controlplane_api.service_cors import add_optional_service_cors
from controlplane_api.health import router as health_router
from controlplane_api.version import router as version_router
from controlplane_db.session import normalize_database_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from user_service.infrastructure.payment_succeeded_consumer import (
    build_payment_succeeded_consumer,
)
from user_service.interfaces.api.operator_routes import router as operator_router
from user_service.interfaces.api.routes import router as user_api_router
from user_service.middleware import UserServiceDbMiddleware
from user_service.account_closure import router as closure_router
from user_service.closure_proxy import router as closure_actions_router
from user_service.closure_proxy import read_router as lifecycle_read_router
from user_service.closure_public_database import check_public_database

logger = get_logger(__name__)


def create_app(
    *,
    test_event_sink: list | None = None,
    service_name: str | None = None,
) -> FastAPI:
    svc_name = service_name or settings.service_name

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if any(os.environ.get(name) for name in (
            "ACCOUNT_CLOSURE_WORKER_DATABASE_URL", "ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET",
        )):
            raise RuntimeError("Private closure credentials cannot be mounted in the public service")
        if any(os.environ.get(name) for name in (
            "PASSWORD_RESET_DATABASE_URL", "PASSWORD_RESET_KEYCLOAK_CLIENT_SECRET",
        )):
            raise RuntimeError("Private password reset credentials cannot be mounted in the public service")
        configure_logging()
        engine = create_async_engine(normalize_database_url(settings.database_url))
        try:
            await check_public_database(engine)
        except BaseException:
            await engine.dispose()
            raise
        maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        configure_session_maker(maker)
        app.state.async_engine = engine
        app.state.session_maker = maker

        if test_event_sink is not None:

            class _ListSink:
                async def publish(
                    self,
                    *,
                    tenant_id,
                    event_type: str,
                    payload: dict,
                    correlation_id: str | None = None,
                ) -> None:
                    test_event_sink.append(
                        {
                            "tenant_id": tenant_id,
                            "event_type": event_type,
                            "payload": payload,
                            "correlation_id": correlation_id,
                        }
                    )

            set_tenant_event_publisher(_ListSink())
        else:
            await install_tenant_event_publisher(service_name=svc_name)
            pay_consumer = build_payment_succeeded_consumer(settings.database_url)
            await pay_consumer.start()
            app.state.event_consumer = pay_consumer

        yield

        event_consumer = getattr(app.state, "event_consumer", None)
        if event_consumer is not None:
            await event_consumer.stop()
        await shutdown_tenant_event_publisher()
        await engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="spanopticon User Service",
        description="Tenant-scoped users, groups, organizations (RLS + Postgres events).",
        version="0.1.0",
    )

    @app.exception_handler(UnauthorizedException)
    async def _unauthorized(_: Request, ex: UnauthorizedException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": ex.message},
        )

    @app.exception_handler(ForbiddenException)
    async def _forbidden(_: Request, ex: ForbiddenException) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": ex.message},
        )

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema
        from fastapi.openapi.utils import get_openapi

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description or "",
            routes=app.routes,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})[
            "BearerAuth"
        ] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Keycloak access token (tenant claim + X-Tenant-ID must match)",
        }
        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi

    app.add_middleware(UserServiceDbMiddleware)
    from user_service.infrastructure.event_http import consumer_router
    app.include_router(consumer_router(), prefix='/api/v1')
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(version_router)
    app.include_router(user_api_router, prefix="/api/v1")
    from user_service.identity_api import router as identity_router
    app.include_router(identity_router,prefix="/api/v1")
    app.include_router(operator_router, prefix="/api/v1")
    app.include_router(closure_router, prefix="/api/v1")
    app.include_router(closure_actions_router, prefix="/api/v1")
    app.include_router(lifecycle_read_router, prefix="/api/v1")
    add_optional_service_cors(app, env_var="USER_SERVICE_CORS_ORIGINS")
    logger.info("User service: UserServiceDbMiddleware + /api/v1 routes + optional CORS")
    from controlplane_api.metrics import install_http_metrics

    install_http_metrics(app)
    return app


app = create_app()
