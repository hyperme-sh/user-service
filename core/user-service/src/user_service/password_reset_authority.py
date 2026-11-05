"""Private, purpose-bound password-action authority; never mount in the public app."""
from contextlib import asynccontextmanager
import asyncio
import hmac
import os
import ssl
import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from controlplane_db.models import Tenant
from user_service.infrastructure.persistence.repos import SqlUserRepository
from user_service.interfaces.api.operator_routes import require_support, _tenant
from user_service.password_reset import (
    KeycloakPasswordResetClient, PasswordResetTargetMismatch, PasswordResetUnavailable,
    operations_secret, tls_context,
)


class ResetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    email: str = Field(min_length=3, max_length=512)


def database_options():
    try:
        raw = os.environ["PASSWORD_RESET_DATABASE_URL"]
        url = make_url(raw)
        if (url.drivername != "postgresql+asyncpg" or not url.host or not url.database
                or not url.username or not url.password
                or raw == os.environ.get("DATABASE_URL")
                or raw == os.environ.get("ACCOUNT_CLOSURE_WORKER_DATABASE_URL")):
            raise ValueError
        local = (os.environ.get("FASTAPI_ENV", "").lower() in {"test", "development"}
                 and url.host in {"127.0.0.1", "localhost", "::1"})
        if local:
            tls = False
        else:
            tls = ssl.create_default_context(cafile=os.environ["PASSWORD_RESET_DATABASE_CA"])
        return url, {"ssl": tls}
    except Exception:
        raise PasswordResetUnavailable() from None


async def check_database(engine):
    async with engine.connect() as connection:
        roles = (await connection.execute(text(
            "SELECT rolname,(rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication) "
            "FROM pg_catalog.pg_roles WHERE pg_has_role(session_user,oid,'SET') OR rolname=current_user LIMIT 1001"
        ))).all()
        if not roles or len(roles) > 1000:
            raise PasswordResetUnavailable()
        for role, privileged in roles:
            if privileged:
                raise PasswordResetUnavailable()
            for table in ("public.users", "public.tenants"):
                if await connection.scalar(text(
                    "SELECT has_table_privilege(:role,:table,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
                    "OR has_any_column_privilege(:role,:table,'INSERT,UPDATE,REFERENCES')"
                ), {"role": role, "table": table}) is not False:
                    raise PasswordResetUnavailable()
        for table in ("public.users", "public.tenants"):
            if await connection.scalar(text("SELECT has_table_privilege(current_user,:table,'SELECT')"),
                                       {"table": table}) is not True:
                raise PasswordResetUnavailable()


def create_app():
    @asynccontextmanager
    async def lifespan(app):
        engine = None
        try:
            operations_secret()
            url, options = database_options()
            engine = create_async_engine(url, connect_args=options, pool_pre_ping=True, echo=False)
            await check_database(engine)
            async with httpx.AsyncClient(timeout=3, trust_env=False, follow_redirects=False,
                                         verify=tls_context("PASSWORD_RESET_KEYCLOAK_CA")) as client:
                app.state.identity = KeycloakPasswordResetClient(client)
                app.state.sessions = async_sessionmaker(engine, expire_on_commit=False)
                yield
        except Exception:
            raise PasswordResetUnavailable() from None
        finally:
            if engine is not None:
                await engine.dispose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        response = None
        try:
            if request.url.path != "/internal/password-reset" or request.method != "POST":
                response = JSONResponse(status_code=404, content={"detail": "Not found"})
            elif not hmac.compare_digest(request.headers.get("X-Password-Reset-Token", "").encode(),
                                         operations_secret().encode()):
                response = JSONResponse(status_code=403, content={"detail": "Password reset authority required"})
            else:
                async with asyncio.timeout(10):
                    try:
                        claims = await asyncio.to_thread(require_support, request)
                    except HTTPException as error:
                        return JSONResponse(status_code=error.status_code,
                                            content={"detail": "Operator authority required"},
                                            headers={"Cache-Control": "no-store"})
                    request.state.reset_tenant = _tenant(claims)
                    response = await call_next(request)
        except Exception:
            response = JSONResponse(status_code=503, content={"detail": "Password reset unavailable"})
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/internal/password-reset")
    async def reset(request: Request, body: ResetRequest):
        if request.state.reset_tenant != body.tenant_id:
            return JSONResponse(status_code=403, content={"detail": "Operator tenant mismatch"})
        async with app.state.sessions() as session:
            await session.execute(text("SET TRANSACTION READ ONLY"))
            await session.execute(text("SET LOCAL statement_timeout='5000ms'"))
            await session.execute(text("SELECT set_config('app.current_tenant_id', :tenant, true)"),
                                  {"tenant": str(body.tenant_id)})
            user = await SqlUserRepository(session).get(body.tenant_id, body.user_id)
            active = await session.scalar(select(Tenant.is_active).where(Tenant.id == body.tenant_id))
            if (user is None or not user.is_active or not user.keycloak_sub or active is not True
                    or user.email.strip().casefold() != body.email.strip().casefold()):
                return JSONResponse(status_code=409, content={"detail": "Password reset identity mismatch"})
            try:
                await app.state.identity.send(subject=user.keycloak_sub, email=user.email)
            except PasswordResetTargetMismatch:
                return JSONResponse(status_code=409, content={"detail": "Password reset identity mismatch"})
        return {"sent": True}

    return app
