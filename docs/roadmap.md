# Platform Roadmap and Acceptance Evidence

This roadmap is an engineering plan, not a statement that future capabilities exist.
It prioritizes completion of the current CI/CD milestone before additional
infrastructure. No paid cloud resources, Terraform applies, or deployments are
authorized by this plan.

## Status summary

| Area | Status on 2026-10-22 | Evidence / boundary |
|---|---|---|
| Training and evaluation | Implemented; test evaluation gated | Milestone 1 report, readiness report, governance tests |
| FastAPI and Docker | Implemented and locally verified | Milestone 2 report; real saved-model container smoke |
| CI/CD | **Implemented locally; hosted verification pending** | CI and manual release workflows exist; no hosted run or image publication has been verified |
| IaC/Terraform | Planned | No Terraform configuration/state or cloud resources |
| Linux operations | Basic container controls verified locally | Non-root, read-only mount, health check, local cgroup limits; no production ops |
| Kubernetes | Future, not implemented | No manifests, cluster, scheduling, or autoscaler validation |
| Streaming/drift/observability | Future, not implemented | No ingestion, drift service, telemetry collection, or alert evaluation |
| Multi-tenancy | **Not implemented; do not claim support** | No identity provider, authz, tenant context, storage policy, or isolation tests |
| Incident response | Planned | No operational incidents, failure drills, or recovery objectives measured |

## Ordered milestones

### M3 — CI/CD and artifact integrity (implemented locally; hosted verification pending)

Keep this milestone limited to repository automation and reproducible build/release
evidence. The workflows now implement these gates, but hosted runs and a manually
authorized first release remain pending. Do not add Terraform, Kubernetes, streaming,
or cloud deployment to M3.

**Scope**

- Add CI for supported Python versions, lockfile checks, tests, Ruff, syntax/type
  checks if selected, Docker build, and image/config checks.
- Add dependency and container vulnerability scanning plus SBOM generation and
  retention. Pin action/tool versions; define severity policy and exception expiry.
- Build reproducibly from `uv.lock` and digest-pinned base; attach source revision,
  build provenance, image digest, dependency lock, and schema version to the build.
- Validate a mounted trusted artifact in non-publishing CI without training or
  scoring the held-out test set. CI must never run final test evaluation.
- Separate pull-request validation from release: no registry push/deploy until a
  protected, approved release path is designed.

**Acceptance criteria**

1. Pull-request CI runs tests, Ruff, lock validation, Docker build, and secret scan
   from a clean checkout; all required checks are branch-protection eligible.
2. CI proves the default training path does not touch `indices["test"]`, create test
   metrics, or select a candidate using test data.
3. Build from the same commit and lockfile records its image digest and SBOM; image
   provenance identifies the source revision and pinned base digest.
4. Secret/dependency/image findings fail the configured severity threshold; any
   exception has a named owner, rationale, compensating control, and expiry date.
5. A failed test/build/scan blocks release. CI does not apply infrastructure or
   publish/deploy without explicit approval.

**Portfolio evidence:** workflow files, passing CI run URL/log, SBOM, image digest,
provenance attestation, scan summary, reviewed CI design record, and a short
reproduction guide. Clearly mark any CI permission not exercised.

### M4 — Telemetry contract and generalization evidence

Define and test a versioned Zeek-to-v1 normalizer without silently accepting raw logs
at the prediction API. Resolve `conn.log` direction, type normalization, timestamps,
and DNS/TLS/HTTP/weird joins by connection UID. Obtain a new independent collection
with time/session/device/scenario identifiers and documented permissions before
claiming operational generalization.

**Acceptance criteria:** golden fixture tests for each protocol-log mapping and
missing-field semantics; no target/identifier leakage; malformed and late/missing
joins measured; data provenance recorded; temporal and held-out-device/scenario
evaluation performed once with a preregistered protocol. The current test set remains
closed to tuning.

**Portfolio evidence:** data-flow diagram, schema/mapping specification, sanitized
fixtures, join-quality report, evaluation protocol, and independently generated
validation results with limitations.

### M5 — Identity and authorization design (prerequisite to shared access)

Select an identity provider and threat model through ADR/design review. Prototype
authentication and authorization before any shared tenant launch. Until this phase
passes all gates, serve only within a single trusted operator boundary.

**Acceptance criteria**

1. Caller tenant identity comes only from cryptographically validated identity or
   workload credentials; caller-controlled body/header tenant IDs are ignored or
   rejected.
2. Every endpoint and asynchronous operation enforces tenant, role, model, and
   operation policy, with fail-closed behavior and immutable request context.
3. Automated two-tenant tests deny forged claims and cross-tenant inference, model
   selection, cache, audit, and persisted-data access; test deployed policy as well
   as unit logic.
4. Logs/metrics contain no raw network payload or sensitive/high-cardinality tenant
   identifiers. Security review signs off on isolation, deletion, retention, and
   administrative access controls.

**Portfolio evidence:** threat model, identity/authz ADR, policy tests including
negative cases, security review record, and test output. Do not label the system
multi-tenant until these gates pass.

### M6 — Reliability, observability, drift, and incident operations

Start with platform instrumentation and runbooks for the single serving service.
Add drift monitoring only after an approved feature/label feedback source and
tenant-safe aggregation policy exist. Add a separate service only if operational
ownership or scaling needs warrant it.

**Acceptance criteria (proposed targets requiring baseline approval)**

- Load test: 20 requests/second for 30 minutes, p95 ≤250 ms, server errors <1%,
  no OOM/restart; use representative normalized records and record machine/image
  dimensions.
- Readiness: valid pinned model reaches ready ≤60 seconds; absent/corrupt/incompatible
  model stays unready and raises an actionable alert.
- Recovery: restore non-production from a pinned image/model reference ≤30 minutes;
  verify model ID/schema/config and no unapproved artifact drift.
- Failure injection covers model/schema loss, authz denial, slow inference, memory
  pressure, process/worker loss, telemetry queue back-pressure, and state/backup
  restore. Record detection, mitigation, recovery, and data loss for every drill.
- Alerts have thresholds tied to measured baselines, an owner, severity, and runbook.
  Alert routing is tested, not inferred from config.
- Provisional availability objective: 99.5% rolling 30 days only after production
  deployment and telemetry exist; do not claim it before measurement.

**Portfolio evidence:** service dashboards with sanitized labels, alert test, load
test report, failure-injection record, incident runbooks, recovery evidence, and
reviewed SLO/error-budget decision.

### M7 — Terraform and environment foundations (approval-gated; no apply by default)

Implement reusable modules only after M3, identity design, threat model, provider
choice, and cost/security review. Keep provider-specific implementation deferred
until justified. The initial Terraform milestone may validate and plan against
non-paid fixtures, but must not create billable resources without explicit approval.

**Design principles**

- Version reusable modules; separate environment roots (dev/stage/prod) and
  identities/state keys/policies.
- Use an approved remote state backend with encryption, state locking, versioning,
  least-privilege access, audit, backup/recovery, and restricted outputs. Never
  commit state, credentials, or secret-bearing plan files.
- Pin providers/modules and commit provider lockfiles. Inputs and image/model
  references are versioned; deployment plans identify source revision and artifact
  digest.
- `fmt`, `validate`, policy/security checks, and reviewed plan are mandatory. Plan
  jobs do not apply; apply requires protected environment approval and operator
  authorization. Drift detection is read-only and alertable.
- Cost estimates and quotas are part of every plan review. No automatic cloud apply.

**Acceptance criteria**

1. Module tests use mocks/local providers where possible; `terraform fmt -check`,
   `terraform validate`, policy checks, and plan succeed in a clean CI environment.
2. Separate non-secret environment configs cannot read/write each other's state;
   backend lock contention is tested and state recovery documented.
3. Plan output is reviewed, sanitized, associated to commit and provider/module
   locks, and requires explicit protected approval before apply.
4. A destroy/recovery exercise in an approved non-production environment has
   documented costs and no cross-environment access. Do not run this criterion until
   cloud spending is approved.

**Portfolio evidence:** module source/tests, state-threat model, backend decision
ADR, sanitized plans, policy results, cost estimate, review record, and a reproducible
no-apply validation log.

### M8 — Kubernetes scheduling and scaling (only if justified and approved)

Retain Docker/local operation until availability, rollout, or scaling requirements
justify Kubernetes overhead. No cluster is part of the current implementation.

**Acceptance criteria**

- Serving pods schedule onto labeled CPU worker nodes with requests/limits based on
  M6 measurements; GPU pools require a measured/approved requirement.
- Pod topology spread, readiness/liveness, termination grace, disruption budget,
  service account permissions, network policy, non-root security context, and secret
  mounts are tested.
- HPA targets a measured bottleneck; worker-node autoscaling, quotas, min/max,
  cooldown and cold model-load behavior are tested under load and scale-in.
- A worker node drain/failure and pod reschedule preserve readiness/recovery targets.
- Every resource is provisioned through approved Terraform; no console-only drift.

**Portfolio evidence:** scheduling rationale, sanitized manifests/plans, load and
node-drain tests, autoscaling timeline, cost envelope, and rollback runbook.

“Node” in this roadmap means Kubernetes worker node. Node.js is not planned: the
application and serving stack are Python-native, and no genuine Node.js requirement
has been identified.

## Engineering evidence across milestones

| Competency | Evidence expected |
|---|---|
| Technical architecture | Current/target diagrams, data-flow and trust boundaries, versioned contracts |
| Design reviews | Review scope, alternatives, threat/cost/reliability analysis, action owners, approval state |
| ADR practice | Context/decision/consequences, rejected options, status, supersession links |
| Infrastructure as Code | Tested reusable Terraform modules, state security/locking, environment plans |
| Linux/platform operations | Permission/network/resource diagnostics, container hardening, measured recovery |
| Multi-tenancy | Verified identity-derived scope and automated adversarial cross-tenant denial tests |
| Incident response | Runbooks, tested alert routing, failure injection, measured recovery/postmortems |
| AI/ML infrastructure | Immutable model/schema provenance, validation/test governance, drift and data-quality boundaries |

Evidence is only marked **implemented and verified** after an executable test or
review artifact exists. Plans, diagrams, and unexecuted configuration remain
**planned**.
