from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from api.common.exceptions import ForbiddenException, UnauthorizedException
from api.common.logging import configure_logging
from api.common.utils import get_logger
from api.core.config import settings
from api.infrastructure.messaging.tenant_event_publisher import (
    KafkaTenantEventPublisher,
    NoOpTenantEventPublisher,
    set_tenant_event_publisher,
)
from api.infrastructure.persistence.db_session import configure_session_maker
from api.interfaces.api_controllers.health_endpoint import router as health_router
from controlplane_db.session import normalize_database_url
from controlplane_events import AioKafkaEventProducer
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from user_service.infrastructure.payment_succeeded_consumer import (
    build_payment_succeeded_consumer,
)
from user_service.interfaces.api.routes import router as user_api_router
from user_service.middleware import UserServiceDbMiddleware

logger = get_logger(__name__)


def create_app(
    *,
    test_event_sink: list | None = None,
    service_name: str | None = None,
) -> FastAPI:
    svc_name = service_name or settings.service_name

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        engine = create_async_engine(normalize_database_url(settings.database_url))
        maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
        configure_session_maker(maker)
        app.state.async_engine = engine

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
        elif settings.kafka_bootstrap_servers:
            kafka_producer = AioKafkaEventProducer(
                settings.kafka_bootstrap_servers,
                client_id=f"{svc_name}-events",
            )
            await kafka_producer.start()
            set_tenant_event_publisher(
                KafkaTenantEventPublisher(
                    kafka_producer,
                    settings.kafka_events_topic,
                    svc_name,
                )
            )
            app.state.kafka_producer = kafka_producer
            pay_consumer = build_payment_succeeded_consumer(
                settings.kafka_bootstrap_servers,
                settings.kafka_events_topic,
            )
            await pay_consumer.start()
            app.state.kafka_payment_consumer = pay_consumer
        else:
            set_tenant_event_publisher(NoOpTenantEventPublisher())

        yield

        k_pay = getattr(app.state, "kafka_payment_consumer", None)
        if k_pay is not None:
            await k_pay.stop()
        set_tenant_event_publisher(None)
        kp = getattr(app.state, "kafka_producer", None)
        if kp is not None:
            await kp.stop()
        await engine.dispose()

    app = FastAPI(
        lifespan=lifespan,
        title="Panopticon User Service",
        description="Tenant-scoped users, groups, organizations (RLS + Kafka).",
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
    app.include_router(health_router, prefix="/api/v1")
    app.include_router(user_api_router, prefix="/api/v1")
    logger.info("User service: UserServiceDbMiddleware + /api/v1 routes")
    return app


app = create_app()
