"""Explicit, atomic reconciliation of the preserved public identity RLS policies.

This is operator tooling, never application startup or a replacement baseline.
Unknown policy definitions are refused before any ALTER POLICY statement.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import uuid

from sqlalchemy import create_engine, text

TABLES = ('groups', 'roles', 'user_group_memberships', 'users')
COMMANDS = {'select': 'r', 'insert': 'a', 'update': 'w', 'delete': 'd'}
SETTING = "current_setting('app.current_tenant_id'::text, true)"
OLD = f"(({SETTING} = ''::text AND tenant_id IS NULL) OR ({SETTING} <> ''::text AND tenant_id IS NOT NULL AND tenant_id = ({SETTING})::uuid))"
FIXED = f"(({SETTING} = ''::text AND tenant_id IS NULL) OR ({SETTING} <> ''::text AND tenant_id IS NOT NULL AND tenant_id = nullif({SETTING}, ''::text)::uuid))"


def _snapshot(connection):
    rows = connection.execute(text("""SELECT c.relname AS table_name, c.relrowsecurity, c.relforcerowsecurity,
        p.polname, p.polcmd, p.polpermissive, p.polroles::text AS roles,
        pg_get_expr(p.polqual,p.polrelid) AS using_expr,
        pg_get_expr(p.polwithcheck,p.polrelid) AS check_expr
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        LEFT JOIN pg_catalog.pg_policy p ON p.polrelid=c.oid
        WHERE n.nspname='public' AND c.relname IN ('groups','roles','user_group_memberships','users')
        ORDER BY c.relname,p.polname""")).mappings().all()
    return [dict(r) for r in rows]


def _digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def reconcile(connection, *, apply=False):
    """Caller owns the transaction; application roles need no new privileges."""
    connection.exec_driver_sql("SET LOCAL lock_timeout='5s'")
    # All target locks precede inspection: policy writers cannot race validation.
    connection.exec_driver_sql('LOCK TABLE '+','.join('public.'+n for n in TABLES)+' IN ACCESS EXCLUSIVE MODE')
    before = _snapshot(connection)
    # Ask this PostgreSQL server to canonicalize both exact allowed predicates.
    temporary = 'identity_rls_expected_' + uuid.uuid4().hex
    connection.exec_driver_sql(f'CREATE TEMP TABLE "{temporary}" (tenant_id uuid) ON COMMIT DROP')
    for name, expression in [('old',OLD),('fixed',FIXED)]:
        connection.exec_driver_sql(f'CREATE POLICY {name} ON pg_temp."{temporary}" USING ({expression}) WITH CHECK ({expression})')
    expected = dict(connection.execute(text("""SELECT polname,pg_get_expr(polqual,polrelid)
        FROM pg_catalog.pg_policy WHERE polrelid=CAST(:table AS regclass)"""), {'table':'pg_temp.'+temporary}).all())
    required = {(t,'tenant_isolation_'+c):c for t in TABLES for c in COMMANDS}
    if len(before) != len(required) or {(r['table_name'],r['polname']) for r in before} != set(required):
        raise ValueError('Historical identity policy inventory differs')
    changes = []
    for row in before:
        command = required[row['table_name'],row['polname']]
        if not row['relrowsecurity'] or not row['polpermissive'] or row['roles'] != '{0}' or row['polcmd'] != COMMANDS[command]:
            raise ValueError('Historical identity policy flags differ')
        expressions = [row['using_expr']] if command == 'delete' or command == 'select' else [row['check_expr']] if command == 'insert' else [row['using_expr'],row['check_expr']]
        unused = row['using_expr'] if command == 'insert' else row['check_expr'] if command in ('select','delete') else None
        if unused is not None or any(e not in expected.values() for e in expressions):
            raise ValueError('Historical identity policy definition differs')
        if any(e == expected['old'] for e in expressions):
            changes.append((row['table_name'],row['polname'],command))
    if apply:
        for table, policy, command in changes:
            clause = '' if command == 'insert' else f' USING ({FIXED})'
            if command in ('insert','update'):
                clause += f' WITH CHECK ({FIXED})'
            connection.exec_driver_sql(f'ALTER POLICY {policy} ON public.{table}'+clause)
    after = _snapshot(connection)
    return {'schema_version':1, 'status':'reconciled' if apply and changes else 'pending' if changes else 'current',
            'policies':len(before), 'changed':len(changes) if apply else 0,
            'before_sha256':_digest(before), 'after_sha256':_digest(after)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url-file', type=Path, required=True)
    parser.add_argument('--apply', action='store_true', help='Apply the validated repair atomically')
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    from controlplane_events.store import normalize_sync_url
    engine = create_engine(normalize_sync_url(args.database_url_file.read_text().strip()))
    try:
        with engine.begin() as db:
            receipt = reconcile(db, apply=args.apply)
        args.receipt.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    finally:
        engine.dispose()


if __name__ == '__main__':
    main()
