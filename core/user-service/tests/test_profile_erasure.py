"""Profile owner erasure keeps financial evidence and other scopes intact."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from controlplane_db.models import (
    BillingRecord,
    User,
    UserPasskey,
    UserPreference,
    UserWalletBinding,
)
from controlplane_tenancy.account_profile import (
    disable_subject_memberships,
    purge_retired_profile,
)
from controlplane_tenancy.tenant_membership import retire_identity
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def test_erasure_fences_profile_and_preserves_bills_and_other_tenants(
    closure_sync_url, seed
):
    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)
    subject = str(uuid.uuid4())
    identifiers = {seed.ta: uuid.uuid4(), seed.tb: uuid.uuid4()}
    closed = datetime.now(UTC) - timedelta(days=89)
    bill = uuid.uuid4()
    email = subject + "@example.invalid"

    async def scope(session, tenant):
        await session.execute(
            text("SELECT set_config('app.current_tenant_id',:t,true)"),
            {"t": str(tenant) if tenant else ""},
        )

    try:
        async with maker.begin() as session:
            for tenant, identifier in identifiers.items():
                session.add(
                    User(
                        id=identifier,
                        tenant_id=tenant,
                        keycloak_sub=subject,
                        email=email,
                        first_name="Private",
                        last_name="Person",
                        gender="unspecified",
                        is_active=True,
                        password="not-real-password",
                        image_url="https://private.example/photo",
                        sociacl_attributes={"private": "value"},
                    )
                )
            await session.flush()
            for tenant, identifier in identifiers.items():
                session.add(
                    UserPreference(
                        tenant_id=tenant,
                        user_id=identifier,
                        preferences={"private": "choice"},
                    )
                )
                session.add(
                    UserPasskey(
                        tenant_id=tenant,
                        user_email=email,
                        credentials=[{"credential": "not-real"}],
                    )
                )
            session.add(
                BillingRecord(
                    id=bill,
                    tenant_id=seed.ta,
                    scope="user",
                    actor="user",
                    user_id=identifiers[seed.ta],
                    payment_type="card",
                    currency="USD",
                    amount=123,
                    status="paid",
                    extra_metadata={"tax-receipt": "retained"},
                )
            )
            session.add(
                UserWalletBinding(
                    keycloak_sub=subject,
                    email=email,
                    wallet_address="0x" + uuid.uuid4().hex + "01234567",
                )
            )
            await session.flush()
            await retire_identity(session, subject, closed)
        async with maker.begin() as session:
            await scope(session, seed.tb)
            with pytest.raises(ValueError, match="matching profile database scope"):
                await disable_subject_memberships(session, seed.ta, subject)
            assert await session.scalar(
                text("SELECT current_setting('app.current_tenant_id',true)")
            ) == str(seed.tb)
        async with maker.begin() as session:
            await scope(session, seed.ta)
            assert await disable_subject_memberships(session, seed.ta, subject) == (
                identifiers[seed.ta],
            )
        with pytest.raises(ValueError, match="window"):
            async with maker.begin() as session:
                await scope(session, seed.ta)
                await purge_retired_profile(
                    session,
                    seed.ta,
                    subject,
                    (identifiers[seed.ta],),
                    verified_closed_at=closed,
                    now=closed + timedelta(days=88),
                )
        async with maker.begin() as session:
            await scope(session, seed.ta)
            deleted = await purge_retired_profile(
                session,
                seed.ta,
                subject,
                (identifiers[seed.ta],),
                verified_closed_at=closed,
                now=closed + timedelta(days=89),
            )
            assert (
                deleted["profiles"] == 1
                and deleted["user_preferences"] == 1
                and deleted["user_passkeys"] == 1
            )
        async with maker.begin() as session:
            await scope(session, seed.ta)
            retry = await purge_retired_profile(
                session,
                seed.ta,
                subject,
                (identifiers[seed.ta],),
                verified_closed_at=closed,
                now=closed + timedelta(days=90),
            )
            assert all(count == 0 for count in retry.values())
            row = await session.get(User, identifiers[seed.ta])
            assert (
                row.keycloak_sub is None
                and row.password is None
                and row.image_url is None
            )
            assert row.sociacl_attributes is None and not row.is_active
            assert row.first_name == row.last_name == ""
            assert row.email.startswith("closed+") and row.email.endswith(
                "@account.invalid"
            )
            billing = await session.get(BillingRecord, bill)
            assert (
                billing.user_id == row.id
                and billing.amount == 123
                and billing.status == "paid"
            )
            assert billing.extra_metadata == {"tax-receipt": "retained"}
        replacement = uuid.uuid4()
        async with maker.begin() as session:
            await scope(session, seed.ta)
            session.add(
                User(
                    id=replacement,
                    tenant_id=seed.ta,
                    keycloak_sub=str(uuid.uuid4()),
                    email=email,
                    first_name="Replacement",
                    last_name="Owner",
                    gender="unspecified",
                    is_active=True,
                )
            )
            session.add(
                UserPasskey(
                    tenant_id=seed.ta,
                    user_email=email,
                    credentials=[{"new": "credential"}],
                )
            )
        async with maker.begin() as session:
            await scope(session, seed.ta)
            await purge_retired_profile(
                session,
                seed.ta,
                subject,
                (identifiers[seed.ta],),
                verified_closed_at=closed,
                now=closed + timedelta(days=90),
            )
            assert (await session.get(User, replacement)).first_name == "Replacement"
            assert (
                await session.execute(
                    select(UserPasskey).where(
                        UserPasskey.tenant_id == seed.ta,
                        UserPasskey.user_email == email,
                    )
                )
            ).scalar_one().credentials == [{"new": "credential"}]
        wrong_subject = str(uuid.uuid4())
        async with maker.begin() as session:
            await retire_identity(session, wrong_subject, closed)
        with pytest.raises(ValueError, match="does not belong"):
            async with maker.begin() as session:
                await scope(session, seed.ta)
                await purge_retired_profile(
                    session,
                    seed.ta,
                    wrong_subject,
                    (identifiers[seed.ta],),
                    verified_closed_at=closed,
                    now=closed + timedelta(days=90),
                )
        with pytest.raises(ValueError, match="Complete matching profile inventory"):
            async with maker.begin() as session:
                await scope(session, seed.ta)
                await purge_retired_profile(
                    session,
                    seed.ta,
                    subject,
                    (identifiers[seed.ta], uuid.uuid4()),
                    verified_closed_at=closed,
                    now=closed + timedelta(days=90),
                )
        async with maker.begin() as session:
            await scope(session, seed.tb)
            other = await session.get(User, identifiers[seed.tb])
            assert (
                other.is_active
                and other.first_name == "Private"
                and other.keycloak_sub == subject
            )
            assert (
                await session.execute(
                    select(UserPasskey).where(
                        UserPasskey.tenant_id == seed.tb,
                        UserPasskey.user_email == email,
                    )
                )
            ).scalar_one()
        async with maker.begin() as session:
            await scope(session, None)
            assert (
                await purge_retired_profile(
                    session,
                    None,
                    subject,
                    (),
                    verified_closed_at=closed,
                    now=closed + timedelta(days=89),
                )
            )["user_wallet_bindings"] == 1
    finally:
        await engine.dispose()


async def test_profile_inventory_cannot_erase_another_subject(closure_sync_url, seed):
    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    maker = async_sessionmaker(engine)
    subject = str(uuid.uuid4())
    other = uuid.uuid4()
    closed = datetime.now(UTC) - timedelta(days=90)
    try:
        async with maker.begin() as session:
            await retire_identity(session, subject, closed)
            session.add(
                User(
                    id=other,
                    tenant_id=seed.ta,
                    keycloak_sub="other-" + subject,
                    email=subject + "@other.invalid",
                    first_name="Other",
                    last_name="Owner",
                    gender="unspecified",
                    is_active=True,
                )
            )
        with pytest.raises(ValueError, match="does not belong"):
            async with maker.begin() as session:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id',:t,true)"),
                    {"t": str(seed.ta)},
                )
                await purge_retired_profile(
                    session,
                    seed.ta,
                    subject,
                    (other,),
                    verified_closed_at=closed,
                    now=datetime.now(UTC),
                )
        async with maker() as session:
            row = await session.get(User, other)
            assert row.is_active and row.first_name == "Other"
    finally:
        await engine.dispose()


@pytest.mark.parametrize("restricted", [False, True])
async def test_legacy_history_deletion_requires_full_reference_proof(
    closure_sync_url, seed, restricted
):
    from controlplane_db.models import ChatHistoryAI, ChatSessionAI
    from sqlalchemy import create_engine

    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)
    subject = str(uuid.uuid4())
    owner, other, personal, shared = (uuid.uuid4() for _ in range(4))
    closed = datetime.now(UTC) - timedelta(days=90)
    role = "profile_reader_" + uuid.uuid4().hex
    async with maker.begin() as session:
        for identifier, tenant, sub in (
            (owner, seed.ta, subject),
            (other, seed.tb, "other-" + subject),
        ):
            session.add(
                User(
                    id=identifier,
                    tenant_id=tenant,
                    keycloak_sub=sub,
                    email=str(identifier) + "@example.invalid",
                    first_name="Private",
                    last_name="Person",
                    gender="unspecified",
                    is_active=True,
                )
            )
        for identifier in (personal, shared):
            session.add(
                ChatHistoryAI(
                    id=identifier,
                    tenant_id=seed.ta,
                    histories=[{"text": "private history"}],
                )
            )
        await session.flush()
        for actor, tenant, history in (
            (owner, seed.ta, personal),
            (owner, seed.ta, shared),
            (other, seed.tb, shared),
        ):
            session.add(
                ChatSessionAI(
                    tenant_id=tenant,
                    user_id=actor,
                    session_id=uuid.uuid4(),
                    history_id=history,
                )
            )
        await session.flush()
        await retire_identity(session, subject, closed)
    sync = create_engine(closure_sync_url)
    if restricted:
        with sync.begin() as cx:
            cx.execute(text(f"CREATE ROLE {role} NOBYPASSRLS"))
            cx.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
            cx.execute(text(f"GRANT SELECT ON identity_retirements TO {role}"))
            cx.execute(
                text(
                    f"GRANT SELECT,UPDATE ON users,chat_histories_ai,chat_sessions_ai TO {role}"
                )
            )
            cx.execute(
                text(f"GRANT DELETE ON chat_sessions_ai,chat_histories_ai TO {role}")
            )
    try:
        if restricted:
            with pytest.raises(ValueError, match="history owner authority"):
                async with maker.begin() as session:
                    await session.execute(text(f"SET LOCAL ROLE {role}"))
                    await session.execute(
                        text("SELECT set_config('app.current_tenant_id',:t,true)"),
                        {"t": str(seed.ta)},
                    )
                    await purge_retired_profile(
                        session,
                        seed.ta,
                        subject,
                        (owner,),
                        verified_closed_at=closed,
                        now=datetime.now(UTC),
                    )
            async with maker() as session:
                assert (await session.get(User, owner)).first_name == "Private"
                assert await session.get(ChatHistoryAI, personal) is not None
        else:
            async with maker.begin() as session:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id',:t,true)"),
                    {"t": str(seed.ta)},
                )
                result = await purge_retired_profile(
                    session,
                    seed.ta,
                    subject,
                    (owner,),
                    verified_closed_at=closed,
                    now=datetime.now(UTC),
                )
                assert result["chat_sessions_ai"] == 2
                assert result["chat_histories_ai"] == 1
                assert result["shared_chat_histories"] == 1
            async with maker() as session:
                assert await session.get(ChatHistoryAI, personal) is None
                assert await session.get(ChatHistoryAI, shared) is not None
                remaining = (
                    (
                        await session.execute(
                            select(ChatSessionAI).where(
                                ChatSessionAI.history_id == shared
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                assert len(remaining) == 1 and remaining[0].user_id == other
            # The last owner is in B while the history is physically in A.
            # Both successful erasures must not leave an undiscoverable orphan.
            async with maker.begin() as session:
                await retire_identity(session, "other-" + subject, closed)
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id',:t,true)"),
                    {"t": str(seed.tb)},
                )
                result = await purge_retired_profile(
                    session,
                    seed.tb,
                    "other-" + subject,
                    (other,),
                    verified_closed_at=closed,
                    now=datetime.now(UTC),
                )
                assert result["chat_sessions_ai"] == 1
                assert result["chat_histories_ai"] == 1
                assert result["shared_chat_histories"] == 0
            async with maker() as session:
                assert await session.get(ChatHistoryAI, shared) is None
                assert (
                    not (
                        await session.execute(
                            select(ChatSessionAI).where(
                                ChatSessionAI.history_id == shared
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
    finally:
        if restricted:
            with sync.begin() as cx:
                cx.execute(text(f"DROP OWNED BY {role}"))
                cx.execute(text(f"DROP ROLE {role}"))
        sync.dispose()
        await engine.dispose()


async def test_ambiguous_legacy_email_credentials_are_not_deleted(
    closure_sync_url, seed
):
    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    maker = async_sessionmaker(engine)
    subject = str(uuid.uuid4())
    email = subject + "@example.invalid"
    owner, other = uuid.uuid4(), uuid.uuid4()
    closed = datetime.now(UTC) - timedelta(days=90)
    try:
        async with maker.begin() as session:
            for identifier, sub, address in (
                (owner, subject, email),
                (other, "other-" + subject, " " + email + " "),
            ):
                session.add(
                    User(
                        id=identifier,
                        tenant_id=seed.ta,
                        keycloak_sub=sub,
                        email=address,
                        first_name="Private",
                        last_name="Person",
                        gender="unspecified",
                        is_active=True,
                    )
                )
            session.add(
                UserPasskey(
                    tenant_id=seed.ta,
                    user_email=email,
                    credentials=[{"ambiguous": "credential"}],
                )
            )
            await session.flush()
            await retire_identity(session, subject, closed)
        with pytest.raises(ValueError, match="Ambiguous email-owned"):
            async with maker.begin() as session:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id',:t,true)"),
                    {"t": str(seed.ta)},
                )
                await purge_retired_profile(
                    session,
                    seed.ta,
                    subject,
                    (owner,),
                    verified_closed_at=closed,
                    now=datetime.now(UTC),
                )
        async with maker() as session:
            assert (await session.get(User, owner)).keycloak_sub == subject
            assert (
                await session.execute(
                    select(UserPasskey).where(
                        UserPasskey.tenant_id == seed.ta,
                        UserPasskey.user_email == email,
                    )
                )
            ).scalar_one().credentials == [{"ambiguous": "credential"}]
    finally:
        await engine.dispose()


async def test_erasure_refreshes_stale_profiles_and_uses_current_credential_owner(
    closure_sync_url, seed
):
    from sqlalchemy import update

    engine = create_async_engine(
        closure_sync_url.replace("postgresql+psycopg://", "postgresql+asyncpg://")
    )
    maker = async_sessionmaker(engine, expire_on_commit=False)
    identifier, replacement = uuid.uuid4(), uuid.uuid4()
    subject = str(uuid.uuid4())
    original = subject + "@original.invalid"
    current = subject + "@current.invalid"
    closed = datetime.now(UTC) - timedelta(days=90)
    try:
        async with maker.begin() as session:
            session.add(
                User(
                    id=identifier,
                    tenant_id=seed.ta,
                    keycloak_sub=subject,
                    email=original,
                    first_name="Original",
                    last_name="Name",
                    gender="unspecified",
                    is_active=True,
                )
            )
            await session.flush()
            await retire_identity(session, subject, closed)
        async with maker.begin() as stale:
            await stale.execute(
                text("SELECT set_config('app.current_tenant_id',:t,true)"),
                {"t": str(seed.ta)},
            )
            cached = await stale.get(User, identifier)
            assert cached.image_url is None and cached.password is None
            async with maker.begin() as other:
                await other.execute(
                    update(User)
                    .where(User.id == identifier)
                    .values(
                        email=current,
                        image_url="https://private.example/new-photo",
                        password="changed-hash",
                        sociacl_attributes={"new": "private"},
                    )
                )
                other.add(
                    User(
                        id=replacement,
                        tenant_id=seed.ta,
                        keycloak_sub=str(uuid.uuid4()),
                        email=original,
                        first_name="Replacement",
                        last_name="Owner",
                        gender="unspecified",
                        is_active=True,
                    )
                )
                other.add(
                    UserPasskey(
                        tenant_id=seed.ta,
                        user_email=current,
                        credentials=[{"owned": "closing-user"}],
                    )
                )
                other.add(
                    UserPasskey(
                        tenant_id=seed.ta,
                        user_email=original,
                        credentials=[{"owned": "replacement-user"}],
                    )
                )
            result = await purge_retired_profile(
                stale,
                seed.ta,
                subject,
                (identifier,),
                verified_closed_at=closed,
                now=datetime.now(UTC),
            )
            assert result["profiles"] == 1 and result["user_passkeys"] == 1
        async with maker() as session:
            row = await session.get(User, identifier)
            assert (
                row.image_url is None
                and row.password is None
                and row.sociacl_attributes is None
            )
            assert row.first_name == "" and row.email.startswith("closed+")
            remaining = (
                (
                    await session.execute(
                        select(UserPasskey).where(
                            UserPasskey.tenant_id == seed.ta,
                            UserPasskey.user_email.in_([original, current]),
                        )
                    )
                )
                .scalars()
                .all()
            )
            assert len(remaining) == 1 and remaining[0].credentials == [
                {"owned": "replacement-user"}
            ]
    finally:
        await engine.dispose()
