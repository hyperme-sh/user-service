"""Default-off private account-status reads, without closure-worker authority."""
from contextlib import asynccontextmanager
import os
import re

from controlplane_db.session import normalize_database_url
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from user_service.lifecycle_read import check, require_reader
from user_service.middleware import UserServiceDbMiddleware


async def qualify(connection, role, schema):
    """Reject partial visibility, inherited authority, and mutation privileges."""
    if not all(re.fullmatch(r'[a-z][a-z0-9_]{0,62}', value) for value in (role, schema)):
        raise RuntimeError('Account-status role declaration invalid')
    actual = (await connection.execute(text(
        "SELECT current_user, current_schema(), current_setting('transaction_read_only'), "
        "rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication, "
        "EXISTS(SELECT 1 FROM pg_auth_members WHERE member=current_user::regrole) "
        "FROM pg_roles WHERE rolname=current_user"
    ))).one()
    if actual != (role, schema, 'on', False, False):
        raise RuntimeError('Account-status role refused')
    if await connection.scalar(text(
        "SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
        "AND p.prosecdef AND has_function_privilege(current_user,p.oid,'EXECUTE'))"
    )) is not False:
        raise RuntimeError('Account-status function authority refused')
    if await connection.scalar(text(
        "SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
        "AND c.relkind IN ('r','p','v','m','f') AND "
        "(has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
        "OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES')))"
    )) is not False:
        raise RuntimeError('Account-status write authority refused')
    if await connection.scalar(text(
        "SELECT has_database_privilege(current_user,current_database(),'CREATE') OR "
        "EXISTS(SELECT 1 FROM pg_namespace WHERE nspname !~ '^pg_' "
        "AND nspname <> 'information_schema' AND has_schema_privilege(current_user,oid,'CREATE'))"
    )) is not False:
        raise RuntimeError('Account-status schema authority refused')
    for table in ('account_lifecycles', 'identity_retirements'):

        if await connection.scalar(text(
            "SELECT NOT c.relrowsecurity AND has_table_privilege(current_user,c.oid,'SELECT') "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=:schema AND c.relname=:table AND c.relkind IN ('r','p')"
        ), {'schema': schema, 'table': table}) is not True:
            raise RuntimeError('Account-status complete read visibility required')


def create_app():
    @asynccontextmanager
    async def lifespan(app):
        if os.environ.get('ACCOUNT_STATUS_READER_ENABLED', '').lower() != 'true':
            raise RuntimeError('Account-status reader disabled')
        engine = None
        try:
            engine = create_async_engine(normalize_database_url(os.environ['ACCOUNT_STATUS_DATABASE_URL']),
                                         echo=False, pool_pre_ping=True)
            async with engine.begin() as connection:
                await qualify(connection, os.environ['ACCOUNT_STATUS_DATABASE_ROLE'],
                              os.environ['ACCOUNT_STATUS_DATABASE_SCHEMA'])
            app.state.session_maker = async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
            app.state.engine = engine
            yield
        except Exception:
            raise RuntimeError('Account-status reader unavailable') from None
        finally:
            if engine is not None:
                await engine.dispose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(UserServiceDbMiddleware)
    app.add_api_route('/api/v1/internal/account-lifecycle/check', check, methods=['POST'],
                     dependencies=[Depends(require_reader)])

    @app.middleware('http')
    async def opaque_errors(request, call_next):
        try:
            response = await call_next(request)
            response.headers['Cache-Control'] = 'no-store'
            return response
        except Exception:
            return JSONResponse(status_code=503, content={'detail': 'Account-status reader unavailable'},
                                headers={'Cache-Control': 'no-store'})

    @app.get('/internal/ready', dependencies=[Depends(require_reader)])
    async def ready():
        async with app.state.engine.begin() as connection:
            await qualify(connection, os.environ['ACCOUNT_STATUS_DATABASE_ROLE'],
                          os.environ['ACCOUNT_STATUS_DATABASE_SCHEMA'])
        return {'ready': True}

    return app


app = create_app()
