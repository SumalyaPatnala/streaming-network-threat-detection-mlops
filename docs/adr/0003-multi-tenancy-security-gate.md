# ADR 0003: Multi-Tenancy Requires Verified Identity and Isolation

- **Status:** Proposed; requires security and owner approval
- **Date:** 2026-10-22
- **Decision owner:** Not assigned
- **Related review:** [Platform scope review](../design-reviews/platform-scope.md)

## Context

The current FastAPI service has no authentication, authorization, tenant context,
or persisted tenant-isolated data. Its request schema intentionally has no tenant
feature. Claiming shared multi-tenancy without a trusted identity and enforced
authorization would be unsafe.

## Proposed decision

Do not enable shared tenant access until all roadmap M5 acceptance criteria pass.
Tenant identity must be derived from verified identity/workload claims and propagated
as immutable server-side context. Every model operation, inference, cache, audit
record, background task, and persisted datum must be authorized/scoped. Caller input
must never select its own tenant scope.

Prefer ephemeral inference inputs/results. If persistence is required, decide on
tenant isolation, encryption, retention/deletion, backup/restore, and privileged
administrative access through a separate reviewed ADR.

## Alternatives considered

- Trust a `tenant_id` request field: rejected; callers could self-assert another
  tenant.
- Add tenant IDs to logs/metrics without policy: rejected; identification is not
  authorization and may leak sensitive/high-cardinality data.
- Claim multi-tenancy based on separate API keys without authorization tests:
  rejected as incomplete evidence.

## Required evidence before acceptance

Threat model, chosen identity provider, deny-by-default policy, two-tenant adversarial
tests, deployed-policy tests, security review, audit/retention decisions, and explicit
project-owner approval. Until then, status remains proposed and the service remains
single-tenant/local-only.
