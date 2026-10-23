# ADR 0003: Multi-Tenancy Requires Verified Identity and Isolation

- **Status:** Generic OIDC boundary implemented; shared deployment remains gated
- **Date:** 2026-10-23
- **Decision owner:** Project owner selected generic OIDC for this implementation
- **Related review:** [Platform scope review](../design-reviews/platform-scope.md)

## Context

The original service was single-tenant and local-only. This implementation adds
optional OIDC JWT verification and tenant-scoped ingestion, rate limiting, event
lookups, incident triage, and in-memory drift windows. `tenant_id` is required from
the verified token claim and is never accepted from a caller-controlled event field.
Application tests verify JWT claims and cross-tenant read/triage denial.

## Proposed decision

Do not enable shared production access until deployed-policy tests and security
review pass. The application validates signature via configured HTTPS JWKS, issuer,
audience, expiry, subject, `tenant_id`, and roles. Tenant identity is immutable
request context. Tenant-scoped SQL predicates guard event/incident records; metrics
do not use tenant labels. OIDC is opt-in for preserving the existing local API;
ingestion and investigation endpoints fail closed with 503 when it is not configured.

Prefer ephemeral inference inputs/results. If persistence is required, decide on
tenant isolation, encryption, retention/deletion, backup/restore, and privileged
administrative access through a separate reviewed ADR.

The optional SQLite store persists prediction metadata, evidence references, and
triage decisions but never raw feature values. It is single-process, defaults to
memory, uses restrictive local file permissions when configured, and does not
provide encryption at rest, retention/deletion automation, backups, or multi-replica
coordination. The per-tenant rate limit is process-local. These boundaries prevent
the implementation from being presented as production-ready shared tenancy.

## Alternatives considered

- Trust a `tenant_id` request field: rejected; callers could self-assert another
  tenant.
- Add tenant IDs to logs/metrics without policy: rejected; identification is not
  authorization and may leak sensitive/high-cardinality data.
- Claim multi-tenancy based on separate API keys without authorization tests:
  rejected as incomplete evidence.

## Verification and remaining gate

Verified locally: signed JWT issuer/audience/expiry/tenant/role validation tests,
forged tenant-field rejection, tenant-scoped event and incident negative tests,
role-denied triage, and a tenant-specific ingestion quota. Not externally verified:
real identity-provider JWKS, deployed ingress/token configuration, multi-process
rate limiting, persistence recovery, encryption/retention, privileged administration,
and formal security review. Shared production exposure remains prohibited until
those gaps and owner approval are addressed.
