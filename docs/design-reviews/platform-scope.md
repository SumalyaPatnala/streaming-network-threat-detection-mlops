# Design Review: Platform Engineering Roadmap

- **Status:** Application and no-apply infrastructure implemented; production review pending
- **Date:** 2026-10-23
- **Reviewers:** Not assigned; this is not an approval to provision or deploy
- **Related ADRs:** [0002](../adr/0002-no-nodejs-runtime.md),
  [0003](../adr/0003-multi-tenancy-security-gate.md),
  [0004](../adr/0004-terraform-state-and-environments.md)

## Scope

Align the roadmap with AI/ML infrastructure and platform engineering competencies:
CI/CD, Terraform, Linux operations, Kubernetes worker scheduling, technical
architecture, design governance, incident response, platform service boundaries,
and secure multi-tenancy. Implementation added normalized-event HTTP ingestion,
OIDC tenant checks, investigation/triage records, optional Splunk HEC, configurable
PSI monitoring, Prometheus/Grafana definitions, a Helm chart, and GCP Terraform
modules. These are not production deployments.

## Decision proposal

Keep the current model serving service cohesive; introduce logical boundaries first
and split services only for measurable independent scaling, security, reliability,
or ownership needs. Require deployed identity/authz and cross-tenant isolation
evidence before any shared production exposure. GCP is selected for a no-apply
Terraform baseline, but project/state/cost authorization is outstanding. No paid
cloud resources, apply, or deployment are authorized.

Node.js has no identified application requirement and is not planned. Kubernetes
worker-node scheduling/scaling is a future competency and is distinct from the
Node.js runtime.

## Open decisions

- Required branch protections, updated hosted CI run, signing/provenance and scan thresholds
- Independent telemetry dataset and approved Zeek normalization boundary
- Concrete OIDC provider, deployed authorization policy, and tenant persistence requirements
- SLO baselines, monitoring backend, alert routes, and incident ownership
- GCP project, Terraform state bucket/access controls, cost ceiling, cluster necessity

## Acceptance evidence

Use the measurable M3–M8 gates in [the roadmap](../roadmap.md). Unit/integration
tests and no-apply Terraform/Helm validation exist; production acceptance still
requires deployed-provider evidence, security/cost review, and explicit approval.
No paid infrastructure may be provisioned without explicit approval.
