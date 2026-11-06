"""Private TEST financial erasure. No provider I/O, commits, or public routing.

Call only on the coordinator's privileged connection, after native discovery.
Database-bound TEST policy is mandatory; environment variables grant no authority.
All deletion capabilities bind actual locked row images in this transaction.
"""

from __future__ import annotations

import json
import uuid
from collections import defaultdict
from pathlib import Path
from sqlalchemy import text


class TestRetentionUnavailable(RuntimeError):
    __test__ = False


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _table(name):
    return "public." + _quote(name)


def _sql(connection, statement, **params):
    return connection.execute(text(statement), params)


def financial_tables():
    """Known financial source names; grants confer reads, never caller DML."""
    registry = json.loads(
        Path(__file__)
        .with_name("financial_source_registry.json")
        .read_text()
    )
    return tuple(
        sorted(
            set(registry["chains"]["payment_service"]["tables"])
            | {
                "billing_records",
                "hypermesh_leases",
                "hypermesh_orders",
                "hypermesh_payouts",
                "hypermesh_fills",
                "connect_reversal_exposure_observations",
                "hypermesh_jobs",
                "hypermesh_tunnels",
                "hypermesh_tickets",
                "host_organization_bindings",
                "ai_agent_entitlements",
                "marketplace_purchases",
            }
        )
    )


def _scope_identities(subject, life, scopes):
    def identifiers(values):
        if not isinstance(values, list) or len(values) > 100_000:
            raise TestRetentionUnavailable(
                "Malformed original financial identity inventory"
            )
        try:
            result = [str(uuid.UUID(value)) for value in values if type(value) is str]
        except (ValueError, TypeError, AttributeError):
            raise TestRetentionUnavailable(
                "Malformed original financial identity inventory"
            ) from None
        if len(result) != len(values) or len(set(result)) != len(result):
            raise TestRetentionUnavailable(
                "Ambiguous original financial identity inventory"
            )
        return set(result)

    users = {None: identifiers(life["platform_profile"]["user_ids"])}
    aliases = {None: {subject}}
    original_tenants = identifiers(life["scope_tenants"])
    for tenant, ids, effects in scopes:
        key = str(tenant)
        if (
            key not in original_tenants
            or effects.get("profile_inventory_complete") is not True
        ):
            raise TestRetentionUnavailable(
                "Original financial scope inventory required"
            )
        users[key] = identifiers(ids)
        keys = effects.get("api_keys", {}).get("keys", [])
        if not isinstance(keys, list) or any(
            not isinstance(item, dict) or "id" not in item for item in keys
        ):
            raise TestRetentionUnavailable("Original key owner inventory required")
        aliases[key] = {
            subject,
            *(
                "apikey:" + value
                for value in identifiers([item["id"] for item in keys])
            ),
        }
    if set(users) != {None, *original_tenants}:
        raise TestRetentionUnavailable("Complete original financial scopes required")
    return users, aliases


def purge_test_finances(connection, subject, closed_at, *, limit=100):
    """Erase one account's financial rows and FK children; caller commits receipt.

    Real production retention and holds remain in force unless this database was
    explicitly configured by its administrator as TEST. A rollback removes both
    deleted rows and capabilities. Another customer's roots are never selected.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Bounded TEST erasure batch required")
    if (
        _sql(connection, "SELECT public.account_test_data_enabled()").scalar_one()
        is not True
    ):
        raise TestRetentionUnavailable("Database is not configured for TEST erasure")
    _sql(
        connection,
        "SELECT public.account_require_financial_inventory(:s,:at)",
        s=subject,
        at=closed_at,
    )
    _sql(
        connection,
        "SELECT public.account_lock_financial_inventory(:s,:at,NULL)",
        s=subject,
        at=closed_at,
    )
    if (
        _sql(connection, "SELECT public.account_lock_test_data_policy()").scalar_one()
        is not True
    ):
        raise TestRetentionUnavailable("Database TEST policy changed")
    life = _sql(
        connection,
        "SELECT effects FROM public.account_lifecycles WHERE subject=:s",
        s=subject,
    ).scalar_one()
    scopes = _sql(
        connection,
        "SELECT tenant_id,user_ids,effects FROM public.account_lifecycle_scopes WHERE subject=:s",
        s=subject,
    ).all()
    scoped_users, scoped_aliases = _scope_identities(subject, life, scopes)
    user_ids = set().union(*scoped_users.values())
    aliases = set().union(*scoped_aliases.values())
    identities = user_ids | aliases
    # Source relations are owned by these schemas; catalog FKs supply dependent
    # rows. Internal FK triggers remain enabled and may refuse unsafe deletion.
    registry = json.loads(
        Path(__file__)
        .with_name("financial_source_registry.json")
        .read_text()
    )
    root_names = set(registry["chains"]["payment_service"]["tables"]) | {
        "billing_records",
        "hypermesh_leases",
        "hypermesh_orders",
        "hypermesh_payouts",
        "hypermesh_fills",
        "connect_reversal_exposure_observations",
    }
    relations = dict(
        _sql(
            connection,
            "SELECT c.oid,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r'",
        ).all()
    )
    by_name = {name: oid for oid, name in relations.items()}
    fks = _sql(
        connection,
        """SELECT f.conrelid,f.confrelid,
      ARRAY(SELECT a.attname FROM unnest(f.conkey) WITH ORDINALITY k(attnum,ord)
        JOIN pg_catalog.pg_attribute a ON a.attrelid=f.conrelid AND a.attnum=k.attnum ORDER BY k.ord),
      ARRAY(SELECT a.attname FROM unnest(f.confkey) WITH ORDINALITY k(attnum,ord)
        JOIN pg_catalog.pg_attribute a ON a.attrelid=f.confrelid AND a.attnum=k.attnum ORDER BY k.ord)
      FROM pg_catalog.pg_constraint f WHERE f.contype='f' ORDER BY f.oid""",
    ).all()
    # Cross-owner source references intentionally use native guards instead of
    # foreign keys. Follow these exact, tenant-bound relationships as well.
    for child, parent, child_cols, parent_cols in (
        (
            "billing_tax_orders",
            "billing_records",
            ("billing_record_id", "tenant_id"),
            ("id", "tenant_id"),
        ),
        (
            "hypermesh_leases",
            "billing_records",
            ("billing_record_id", "tenant_id"),
            ("id", "tenant_id"),
        ),
        (
            "hypermesh_payouts",
            "hypermesh_leases",
            ("lease_id", "tenant_id"),
            ("id", "tenant_id"),
        ),
        (
            "hypermesh_jobs",
            "hypermesh_leases",
            ("lease_id", "tenant_id"),
            ("id", "tenant_id"),
        ),
        (
            "hypermesh_tunnels",
            "hypermesh_leases",
            ("lease_id", "tenant_id"),
            ("id", "tenant_id"),
        ),
        (
            "hypermesh_tickets",
            "hypermesh_leases",
            ("lease_id", "tenant_id"),
            ("id", "tenant_id"),
        ),
        (
            "hypermesh_fills",
            "hypermesh_orders",
            ("order_id", "tenant_id"),
            ("order_id", "tenant_id"),
        ),
    ):
        if child in by_name and parent in by_name:
            fks.append((by_name[child], by_name[parent], child_cols, parent_cols))
    reachable = {by_name[name] for name in root_names if name in by_name}
    while True:
        expanded = reachable | {
            child
            for child, parent, _, _ in fks
            if parent in reachable and child in relations
        }
        if expanded == reachable:
            break
        reachable = expanded
    # Only the installed definer can lock/write financial sources. The
    # coordinator's role has SELECT and narrowly scoped function execution.
    _sql(
        connection,
        "SELECT public.account_lock_test_financial_sources(:s,:at)",
        s=subject,
        at=closed_at,
    )
    targets = {}
    parents = {}
    more_roots = False
    pending = []
    dependencies = defaultdict(set)
    root_fields = {
        "billing_records": "user_id",
        "hypermesh_leases": "renter_user_id",
        "connect_access_grants": "owner_sub",
        "usdc_deposit_addresses": "user_id",
        "usdc_payment_intents": "user_id",
        "usdc_chain_transfers": "user_id",
        "onramp_sessions": "user_id",
    }
    # Company organizations and approval actors are not personal payer roots.
    # In particular, pricing org_id is opaque: even a literal subject match
    # confers no authority to delete a company's pricing order.
    for name in sorted(root_fields):
        if name not in by_name:
            continue
        # Query owner fields, not arbitrary audit/recipient text. Native billing
        # has two identity forms; their agreement is checked below.
        field = root_fields[name]
        parameter = (
            "people"
            if field == "renter_user_id"
            else ("users" if field == "user_id" else "ids")
        )
        predicate = f"to_jsonb(t)->>'{field}'=ANY(CAST(:{parameter} AS text[]))"
        if name == "billing_records":
            predicate += (
                " OR to_jsonb(t)->'metadata'->>'actor_sub'=ANY(CAST(:ids AS text[]))"
            )
        if name == "billing_records":
            predicate = "(" + predicate + ") AND t.actor <> 'tenant'"
        # Eligibility must precede LIMIT: unrelated tenant rows sharing a
        # directory UUID must never starve this account's bounded batches.
        scoped_predicates = []
        scoped_params = {}
        for index, tenant in enumerate(scoped_users):
            local_users = scoped_users[tenant]
            local_aliases = scoped_aliases[tenant]
            values = (
                local_users | local_aliases
                if field == "renter_user_id"
                else local_aliases if field == "owner_sub" else local_users
            )
            owner = (
                f"to_jsonb(t)->>'{field}'=ANY(CAST(:scope_values_{index} AS text[]))"
            )
            scoped_params[f"scope_values_{index}"] = sorted(values)
            scoped_params[f"scope_tenant_{index}"] = tenant
            if name == "billing_records":
                owner += f" OR to_jsonb(t)->'metadata'->>'actor_sub'=ANY(CAST(:scope_aliases_{index} AS text[]))"
                scoped_params[f"scope_aliases_{index}"] = sorted(local_aliases)
            scoped_predicates.append(
                f"(to_jsonb(t)->>'tenant_id' IS NOT DISTINCT FROM CAST(:scope_tenant_{index} AS text) AND ({owner}))"
            )
        predicate = f"({predicate}) AND (" + " OR ".join(scoped_predicates) + ")"
        rows = _sql(
            connection,
            f"SELECT ctid::text,to_jsonb(t) FROM {_table(name)} t WHERE {predicate} LIMIT :lim",
            ids=sorted(aliases),
            users=sorted(user_ids),
            people=sorted(identities),
            lim=limit + 1,
            **scoped_params,
        ).all()
        if len(rows) > limit:
            more_roots = True
        for locator, data in rows:
            local_users = scoped_users.get(data.get("tenant_id"), set())
            local_aliases = scoped_aliases.get(data.get("tenant_id"), set())
            metadata = data.get("metadata")
            if name == "billing_records" and (
                not isinstance(metadata, dict)
                or (
                    metadata.get("actor_sub") is not None
                    and type(metadata["actor_sub"]) is not str
                )
            ):
                raise TestRetentionUnavailable("Malformed native payer ownership")
            eligible = (
                (field == "user_id" and data.get(field) in local_users)
                or (field == "owner_sub" and data.get(field) in local_aliases)
                or (
                    field == "renter_user_id"
                    and data.get(field) in local_users | local_aliases
                )
                or (
                    name == "billing_records"
                    and metadata.get("actor_sub") in local_aliases
                )
            )
            if not eligible:
                continue
            if len(pending) >= limit:
                more_roots = True
                break
            if name == "billing_records":
                if _sql(
                    connection,
                    """SELECT EXISTS(SELECT 1 FROM public.account_financial_source_bindings b
                    WHERE b.owner='billing' AND b.kind='payment' AND b.resource=:resource
                      AND b.tenant_id IS NOT DISTINCT FROM CAST(:tenant AS uuid)
                      AND b.subject<>:subject)""",
                    resource=str(data["id"]),
                    tenant=data.get("tenant_id"),
                    subject=subject,
                ).scalar_one():
                    raise TestRetentionUnavailable("Shared native billing ownership")
                user, actor = data.get("user_id"), metadata.get("actor_sub")
                if (user is not None and user not in local_users) or (
                    actor is not None and actor not in local_aliases
                ):
                    raise TestRetentionUnavailable("Conflicting native payer ownership")
            if name == "connect_access_grants":
                # Grant/result journals inherit provider mode from their
                # original recipient; neither child carries livemode itself.
                mode = _sql(
                    connection,
                    """SELECT r.livemode FROM public.connect_access_grants g
                    JOIN public.connect_access_states s
                      ON (s.tenant_id,s.host_org_id)=(g.tenant_id,g.host_org_id)
                    JOIN public.connect_recipient_accounts r
                      ON (r.tenant_id,r.host_org_id)=(s.tenant_id,s.host_org_id)
                      AND r.attempt_id=g.enrollment_attempt_id
                      AND r.stripe_account_id=g.account_id
                    WHERE g.ctid=CAST(CAST(:tid AS text) AS tid)""",
                    tid=locator,
                ).scalar_one_or_none()
                if mode is not False:
                    raise TestRetentionUnavailable(
                        "Live or unresolved Connect ancestry is not TEST data"
                    )
            key = (by_name[name], locator)
            if key not in targets:
                targets[key] = (data, 0)
                pending.append(key)
    # Select risk entries only from their original canonical, non-shared binding.
    risk = _sql(
        connection,
        """SELECT r.ctid::text,to_jsonb(r) FROM public.payer_mismatch_accounts r
      WHERE EXISTS(SELECT 1 FROM public.account_financial_source_bindings b WHERE b.subject=:s
        AND b.kind='payer_mismatch_accounts' AND b.resource=r.account_key)
        AND NOT EXISTS(SELECT 1 FROM public.account_financial_source_bindings b WHERE b.subject<>:s
          AND b.kind='payer_mismatch_accounts' AND b.resource=r.account_key) LIMIT :lim""",
        s=subject,
        lim=limit + 1,
    ).all()
    for locator, data in risk:
        key = (by_name["payer_mismatch_accounts"], locator)
        if key not in targets:
            if len(pending) >= limit:
                more_roots = True
                continue
            targets[key] = (data, 0)
            pending.append(key)
    allowed_names = root_names | {
        "hypermesh_jobs",
        "hypermesh_tunnels",
        "hypermesh_tickets",
        "host_organization_bindings",
        "ai_agent_entitlements",
        "marketplace_purchases",
    }
    # Follow all declared foreign keys, including RESTRICT relationships; never
    # disable internal constraints or leave another table pointing at a deletion.
    index = 0
    while index < len(pending):
        parent, locator = pending[index]
        index += 1
        data, depth = targets[(parent, locator)]
        for child, referenced, child_cols, parent_cols in fks:
            if referenced != parent or child not in reachable:
                continue
            predicate = " AND ".join(
                "c." + _quote(a) + " = p." + _quote(b)
                for a, b in zip(child_cols, parent_cols, strict=True)
            )
            rows = _sql(
                connection,
                f"SELECT c.ctid::text,to_jsonb(c) FROM {_table(relations[child])} c JOIN {_table(relations[parent])} p ON {predicate} WHERE p.ctid=CAST(CAST(:tid AS text) AS tid) LIMIT 1001",
                tid=locator,
            ).all()
            for child_tid, child_data in rows:
                if relations[child] not in allowed_names:
                    raise TestRetentionUnavailable(
                        "Unrecognized financial dependency owner"
                    )
                if (
                    "tenant_id" in data
                    and "tenant_id" in child_data
                    and data["tenant_id"] != child_data["tenant_id"]
                ):
                    raise TestRetentionUnavailable("Cross-tenant financial dependency")
                key = (child, child_tid)
                if key != (parent, locator):
                    dependencies[(parent, locator)].add(key)
                if key not in targets:
                    if len(targets) >= 1000:
                        raise TestRetentionUnavailable(
                            "TEST financial dependency batch exceeds limit"
                        )
                    targets[key] = (child_data, depth + 1)
                    parents[key] = (parent, locator)
                    pending.append(key)
    # Source table locks exclude concurrent writers; exact-image capabilities
    # precede every delete without granting source UPDATE. Original
    # native AFTER triggers continue invalidating inventories/epochs normally.
    for (oid, locator), (data, _) in targets.items():
        if data.get("buyer_id") is not None and data["buyer_id"] not in scoped_users.get(data.get("tenant_id"), set()):
            raise TestRetentionUnavailable("Foreign native TEST customer reference")
        if relations[oid] in {
            "hypermesh_leases",
            "hypermesh_orders",
            "hypermesh_fills",
            "hypermesh_payouts",
        }:
            parties = set(
                _sql(
                    connection,
                    f"SELECT DISTINCT p.subject FROM {_table(relations[oid])} t CROSS JOIN LATERAL public.hypermesh_financial_parties(:kind,to_jsonb(t)) p WHERE t.ctid=CAST(CAST(:tid AS text) AS tid) AND p.direct_reference",
                    kind=relations[oid],
                    tid=locator,
                ).scalars()
            )
            local_users = scoped_users.get(data.get("tenant_id"), set())
            extra = parties - {subject} - local_users
            directory_aliases = parties & local_users
            # Historical renter slots contain either a directory UUID or an
            # issuer UUID. A known directory alias is acceptable only if it is
            # not also a different actual issuer identity.
            collision = (
                bool(directory_aliases)
                and _sql(
                    connection,
                    "SELECT EXISTS(SELECT 1 FROM public.users WHERE keycloak_sub=ANY(CAST(:ids AS text[])) UNION ALL SELECT 1 FROM public.identity_retirements WHERE subject=ANY(CAST(:ids AS text[])))",
                    ids=sorted(directory_aliases),
                ).scalar_one()
            )
            if extra or collision:
                raise TestRetentionUnavailable(
                    "Conflicting native Hypermesh payer ownership"
                )
        if data.get("livemode") is True or (
            "chain_id" in data and data["chain_id"] != 84532
        ):
            raise TestRetentionUnavailable(
                "Live or unsupported provider network is not TEST data"
            )
        current = _sql(
            connection,
            f"SELECT to_jsonb(t) FROM {_table(relations[oid])} t WHERE ctid=CAST(CAST(:tid AS text) AS tid)",
            tid=locator,
        ).scalar_one()
        if current != data:
            raise TestRetentionUnavailable("TEST financial source changed")
        parent = parents.get((oid, locator))
        _sql(
            connection,
            "SELECT public.account_stage_test_delete(:s,:at,CAST(:oid AS oid),:tid,CAST(:parent AS oid),:parent_tid)",
            s=subject,
            at=closed_at,
            oid=oid,
            tid=locator,
            parent=parent[0] if parent else None,
            parent_tid=parent[1] if parent else None,
        )
    counts = defaultdict(int)
    remaining = set(targets)
    while remaining:
        leaves = [key for key in remaining if not (dependencies[key] & remaining)]
        if not leaves:
            raise TestRetentionUnavailable(
                "Cyclic financial dependency requires native owner reconciliation"
            )
        for oid, locator in sorted(leaves):
            deleted = _sql(
                connection,
                "SELECT public.account_delete_test_financial_row(:s,:at,CAST(:oid AS oid),:tid)",
                s=subject,
                at=closed_at,
                oid=oid,
                tid=locator,
            ).scalar_one()
            counts[relations[oid]] += deleted
            remaining.remove((oid, locator))
    _sql(connection, "SELECT public.account_clear_test_delete_capabilities()")
    remaining_bindings = _sql(
        connection,
        "SELECT public.account_reconcile_test_financial_bindings(:s,:at)",
        s=subject,
        at=closed_at,
    ).scalar_one()
    return {
        "complete": remaining_bindings == 0 and not more_roots,
        "roots_complete": not more_roots,
        "deleted": sum(counts.values()),
        "remaining": remaining_bindings + int(more_roots),
        "tables": dict(counts),
    }
