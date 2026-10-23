# ADR 0004: Terraform State and Environment Isolation Principles

- **Status:** GCP selected for no-apply configuration; provisioning remains unapproved
- **Date:** 2026-10-23
- **Decision owner:** Project owner selected GCP for this implementation
- **Related review:** [Platform scope review](../design-reviews/platform-scope.md)

## Context

Terraform, remote state, and environment isolation are platform requirements.
The project owner selected GCP for a no-apply Terraform configuration. No
GCP project, state bucket, billing/cost envelope, or deployment identity has
been authorized or configured. No infrastructure has been provisioned.

## Proposed decision

Implement reusable GCP Terraform modules and separate development/production roots.
Use an already approved GCS state bucket with versioning, locking, least privilege,
and audit. Pin provider versions. CI may validate; a plan requires approved project
access and review. Apply requires protected approval and explicit owner
authorization. The current configuration is not evidence of deployed resources.

Do not commit state, credentials, secret-bearing plans, or unreviewed provider
credentials. A no-apply validation milestone may use mocks/local providers. No paid
resource is created by accepting this ADR.

## Alternatives considered

- Local committed state: rejected due to secrets exposure, concurrency, and recovery risk.
- Shared state/identity across environments: rejected due to blast radius and
  environment-crossing authorization risk.
- Select a cloud/backend now without cost/security requirements: deferred.

## Consequences and acceptance gate

The no-apply provider-specific configuration is in
`infra/terraform/`; it validates locally without cloud credentials by disabling
backend initialization. Model artifacts are stored in a private versioned bucket,
but the serving process still uses an explicitly mounted model volume. Acceptance
of deployment requires a state threat model, approved backend bucket, cost/security
review, state access tests, locking and recovery evidence, a reviewed plan, and
explicit owner approval before any apply.
