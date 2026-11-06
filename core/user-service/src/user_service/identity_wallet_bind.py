"""Bind one recovered SIWE address onto the identified Keycloak person."""

from __future__ import annotations

import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from controlplane_db.models import UserWalletBinding
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.siwe import SiweError, checksum_address


@dataclass(frozen=True, slots=True)
class SiweNonce:
    nonce: str
    issued_at: str
    domain: str
    uri: str
    statement: str
    version: str
    chain_id: int
    message: str


@dataclass(frozen=True, slots=True)
class WalletBinding:
    keycloak_sub: str
    email: str | None
    wallet_address: str
    bound_at: datetime




@asynccontextmanager




async def upsert_wallet_binding(
    session: AsyncSession,
    *,
    keycloak_sub: str,
    email: str | None,
    wallet_address: str,
) -> WalletBinding:
    addr = checksum_address(wallet_address)
    taken = await session.execute(
        select(UserWalletBinding).where(UserWalletBinding.wallet_address == addr)
    )
    existing_addr = taken.scalar_one_or_none()
    if existing_addr is not None and existing_addr.keycloak_sub != keycloak_sub:
        raise SiweError("wallet is already bound to another person")

    found = await session.execute(
        select(UserWalletBinding).where(UserWalletBinding.keycloak_sub == keycloak_sub)
    )
    row = found.scalar_one_or_none()
    now = datetime.now(UTC)
    if row is None:
        row = UserWalletBinding(
            id=uuid.uuid4(),
            keycloak_sub=keycloak_sub,
            email=email,
            wallet_address=addr,
            bound_at=now,
        )
        session.add(row)
    else:
        row.wallet_address = addr
        row.email = email
        row.bound_at = now
    await session.flush()
    await session.refresh(row)
    return WalletBinding(
        keycloak_sub=row.keycloak_sub,
        email=row.email,
        wallet_address=row.wallet_address,
        bound_at=row.bound_at,
    )


async def get_wallet_binding(
    session: AsyncSession, keycloak_sub: str
) -> WalletBinding | None:
    found = await session.execute(
        select(UserWalletBinding).where(UserWalletBinding.keycloak_sub == keycloak_sub)
    )
    row = found.scalar_one_or_none()
    if row is None:
        return None
    return WalletBinding(
        keycloak_sub=row.keycloak_sub,
        email=row.email,
        wallet_address=row.wallet_address,
        bound_at=row.bound_at,
    )
