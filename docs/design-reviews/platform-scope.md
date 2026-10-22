# Design Review: Platform Engineering Roadmap

- **Status:** Proposed plan; implementation and owner approval pending
- **Date:** 2026-10-22
- **Reviewers:** Not assigned; this is not an approval to provision or deploy
- **Related ADRs:** [0002](../adr/0002-no-nodejs-runtime.md),
  [0003](../adr/0003-multi-tenancy-security-gate.md),
  [0004](../adr/0004-terraform-state-and-environments.md)

## Scope

Align the roadmap with AI/ML infrastructure and platform engineering competencies:
CI/CD, Terraform, Linux operations, Kubernetes worker scheduling, technical
architecture, design governance, incident response, platform service boundaries,
and secure multi-tenancy.

## Decision proposal

Finish CI/CD and artifact-integrity work before implementing infrastructure. Keep
the current model serving service cohesive; introduce logical boundaries first and
split services only for measurable independent scaling, security, reliability, or
ownership needs. Require explicit identity/authz and cross-tenant isolation evidence
before claiming multi-tenancy. Add Terraform only after provider/state/cost/security
review. No paid cloud resources, apply, or deployment are authorized.

Node.js has no identified application requirement and is not planned. Kubernetes
worker-node scheduling/scaling is a future competency and is distinct from the
Node.js runtime.

## Open decisions

- CI provider, required branch protections, signing/provenance and scan thresholds
- Independent telemetry dataset and approved Zeek normalization boundary
- Identity provider, authorization policy, and tenant persistence requirements
- SLO baselines, monitoring backend, alert routes, and incident ownership
- Cloud provider, Terraform backend/state controls, cost ceiling, cluster necessity

## Acceptance evidence

Use the measurable M3–M8 gates in [the roadmap](../roadmap.md). Each phase remains
planned until its tests, review, and operator evidence are attached. No paid
infrastructure may be provisioned without explicit approval.
