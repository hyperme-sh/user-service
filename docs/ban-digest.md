# Private active-ban fingerprint

`POST /api/v1/internal/operator-bans/digest` accepts only `tenant_id` (UUID).
It requires the existing unique `PLANE_SCOPE_AUTHORITY_TOKEN` bearer credential
and membership in the owner-configured JSON UUID array `PLANE_STATUS_TENANT_IDS`.
The default array is empty. No configuration or credentials are provisioned by
this change. The digest is for Plane #109's explicitly granted private readers.

Every authorized call reads current, unlifted operator bans in a fresh User-owned
transaction with tenant row security. It returns exactly `ban_hash` and
`computed_at` (UTC), with no-store headers. Database failures do not return an
empty-set hash. No user, group, device, label, reason or count is returned.

Canonical version 1 sorts and deduplicates `[subject_kind, canonical UUID]`
pairs. Compact ASCII JSON with sorted keys contains `version:1`, `tenant_id` and
`subjects`. SHA-256 hashes the bytes prefixed by `operator-active-bans-v1` and a
NUL byte; the result is prefixed `sha256-v1:`. Tenant binding prevents unrelated
tenants from sharing an empty-set fingerprint. This is a change indicator, not a
ban decision or authority to disclose the source set. Unknown subject kinds fail.
Plane must refuse stale or unavailable responses, never cache a public copy.
Digest billing activation and existing ban operations remain unchanged.
