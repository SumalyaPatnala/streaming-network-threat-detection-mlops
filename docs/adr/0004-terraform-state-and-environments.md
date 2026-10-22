# ADR 0004: Terraform State and Environment Isolation Principles

- **Status:** Proposed; provider/backend selection and paid provisioning require approval
- **Date:** 2026-10-22
- **Decision owner:** Not assigned
- **Related review:** [Platform scope review](../design-reviews/platform-scope.md)

## Context

Terraform, remote state, and environment isolation are future platform requirements.
No cloud provider, account/project layout, backend, or cost envelope has been selected.
The repository has no Terraform code and no infrastructure has been provisioned.

## Proposed decision

When M3 CI/CD and the required security/design reviews are complete, implement
versioned reusable Terraform modules and separate environment roots and identities.
Use an approved remote state backend with encryption, locking, versioning/recovery,
least privilege, and audit. Pin provider and module versions. CI may validate/plan;
apply requires protected approval and explicit owner authorization.

Do not commit state, credentials, secret-bearing plans, or unreviewed provider
credentials. A no-apply validation milestone may use mocks/local providers. No paid
resource is created by accepting this ADR.

## Alternatives considered

- Local committed state: rejected due to secrets exposure, concurrency, and recovery risk.
- Shared state/identity across environments: rejected due to blast radius and
  environment-crossing authorization risk.
- Select a cloud/backend now without cost/security requirements: deferred.

## Consequences and acceptance gate

Provider-specific module design and operational support remain open. Acceptance
requires state threat model, backend/provider choice, cost/security review, state
access tests, locking and recovery evidence, and owner approval before any apply.
