"""Per-request DB session + RLS GUC from X-Tenant-ID (no host/subdomain resolution)."""

from __future__ import annotations

import uuid

from api.infrastructure.persistence.db_session import (
    get_session_maker,
    reset_db_session,
    set_db_session,
)
from fastapi import Request
from sqlalchemy import event, text
from starlette.middleware.base import BaseHTTPMiddleware


class UserServiceDbMiddleware(BaseHTTPMiddleware):
    """Sets app.current_tenant_id from X-Tenant-ID for RLS; opens one session per request."""

    async def dispatch(self, request: Request, call_next):
        maker = getattr(request.app.state, "session_maker", None)
        if maker is None:
            maker = get_session_maker()
        async with maker() as session:
            token = set_db_session(session)
            apply_scope = None
            sink = getattr(request.app.state, "directory_event_sink", None)
            def committed(sync_session):
                if not sync_session.in_nested_transaction():
                    sink.extend(sync_session.info.pop("directory_events", []))
            def rolled_back(sync_session):
                sync_session.info.pop("directory_events", None)
            if sink is not None:
                session.info["directory_event_sink"] = sink
                event.listen(session.sync_session, "after_commit", committed)
                event.listen(session.sync_session, "after_rollback", rolled_back)
            try:
                tid = None
                raw = request.headers.get("X-Tenant-ID")
                if raw:
                    try:
                        tid = uuid.UUID(str(raw))
                    except ValueError:
                        from starlette.responses import JSONResponse

                        return JSONResponse(
                            status_code=400,
                            content={"error": "Invalid X-Tenant-ID"},
                        )
                    request.state.tenant_id = tid
                else:
                    request.state.tenant_id = None

                # Authentication can call this service's private retirement
                # authority. Do not reserve a connection while awaiting it.
                # Every actual transaction still receives the request's RLS
                # scope, including transactions opened after a checkpoint.
                def apply_scope(sync_session, transaction, connection):
                    if transaction.nested:
                        return
                    connection.execute(
                        text(
                            "SELECT set_config('app.current_tenant_id', :tenant, true)"
                        ),
                        {"tenant": str(tid) if tid else ""},
                    )

                event.listen(session.sync_session, "after_begin", apply_scope)
                response = await call_next(request)
                if response.status_code >= 400:
                    await session.rollback()
                else:
                    await session.commit()
                return response
            except Exception:
                await session.rollback()
                raise
            finally:
                if apply_scope is not None and event.contains(
                    session.sync_session, "after_begin", apply_scope
                ):
                    event.remove(session.sync_session, "after_begin", apply_scope)
                if sink is not None:
                    event.remove(session.sync_session, "after_commit", committed)
                    event.remove(session.sync_session, "after_rollback", rolled_back)
                reset_db_session(token)
