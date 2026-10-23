# Platform Roadmap and Acceptance Evidence

This roadmap distinguishes application-level implementation from external validation
and deployment. The user authorized a local Kind deployment for M5; no paid cloud
resources or Terraform applies are authorized.

## Status summary

| Area | Status on 2026-10-23 | Evidence / boundary |
|---|---|---|
| Training and evaluation | Implemented; test evaluation gated | Milestone 1 report, readiness report, governance tests |
| FastAPI and Docker | Implemented and locally verified | Milestone 2 report; real saved-model container smoke |
| CI/CD | Existing and expanded hosted push CI verified | [M5 feature-branch run passed](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/40007333874), including Helm/Terraform and Trivy; PR event and GHCR release/provenance remain unverified |
| Streaming ingestion | Implemented for normalized HTTP events; external sources not verified | Versioned event envelope, replay fixtures, idempotency, bounded batch; no raw Zeek parser or broker |
| Identity and tenant isolation | Signed-token app-level end-to-end verified; deployed Helm API has no IdP configured | OIDC signature/claims, tenant-scoped SQLite, triage, quotas, negative cross-tenant test; no live or deployed IdP |
| Splunk | Prediction and triage export verified against local HTTPS mock | Actual sink, simulated HEC 503/retry, evidence/correlation/model linkage, SPL and dashboard definitions; no live instance/credentials |
| MLflow model lifecycle | Experiment/artifact tracking implemented; promotion controls incomplete | Explicit artifact selection; no registered-model stage/alias policy or automated promotion/rollback |
| Drift and observability | PSI alert tested; local Prometheus/Grafana deployed and scraped for verification | Synthetic reference only; Prometheus target `up`, 4 alert rules healthy, Grafana dashboard served; no approved operational baseline |
| IaC/Terraform | GCP modules/roots validated; no plan/apply | `terraform fmt` and `validate` pass with backend disabled; no project credentials/state |
| Linux operations | Basic container controls verified locally | Non-root, read-only mount, health check, local cgroup limits; no production ops |
| Local Kubernetes learning lab | Earlier learning workload preserved; separate M5 Helm workload deployed | Real model inference, probes, read-only mount, non-root runtime, schema rejection, and metrics verified in dedicated Kind cluster |
| Helm | Installed and smoke-tested in local Kind | Dev/prod lint/template; local release `m5-platform`, existing workload untouched; SQLite chart blocks replicas >1 |
| Production Kubernetes scheduling/scaling | Not implemented | No production cluster, worker scheduling, autoscaler, or artifact distribution validation |
| Incident response | Human triage workflow implemented; operations not exercised | Analyst acknowledgment/dismissal; no disruptive automation or incident drills |

## M5 — End-to-end platform integration and local verification

**Status:** Local demo completed; external/production dependencies remain unverified.

- The updated image was built and loaded into the existing `network-threat-lab`
  Kind cluster. The development Helm chart installed release `m5-platform` in
  `threat-detection-lab`, alongside and without changing the previous local
  Deployment. The actual saved MLflow artifact remains host-backed and mounted
  read-only; this is not a production distribution method.
- Readiness, liveness, startup, UID 999, read-only model access, and token
  automount settings were inspected. Real saved-model single and batch inference,
  invalid schema rejection, and Prometheus exposition were exercised through the
  deployed Helm Service. Tenant ingestion fails closed in this deployment
  because no identity provider is configured.
- `tests/test_e2e_saved_model.py` drives the actual app/model using signed
  synthetic tenant JWTs and a local TLS mock HEC. The JWKS lookup is test-stubbed;
  JWT signature and claims are checked by the production verifier. The test
  verifies role denial, cross-tenant 404, idempotency and conflicting replay,
  batch prediction, a synthetic PSI threshold alert, prediction and triage HEC
  records, a failed HEC send/retry, and analyst history. No live Splunk or IdP
  was used.
- A temporary, separately named local Docker Compose project verified Prometheus
  metric scraping (`up`), all four alert rule health states, and the provisioned
  Grafana dashboard. These services were stopped after verification.
- GCP Terraform formatting and validation are local-only; no plan, apply, cloud
  account access, or billable resource was used.
- The pushed M5 commit passed the hosted GitHub Actions workflow:
  [run 40007333874](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/40007333874).
- Reproduction and evidence boundaries: [M5 demo guide](milestone-5-end-to-end-demo.md).

## Ordered milestones

### M3 — CI/CD and artifact integrity (hosted CI verified; manual release unexecuted)

Keep this milestone limited to repository automation and reproducible build/release
evidence. The CI workflow passed on the first `main` push. The release workflow
exists but has deliberately not been triggered; no image was published. See the
[Milestone 3 report](../reports/milestone-3-report.md) for the run evidence and
unverified release limitations. Do not add Terraform, Kubernetes, streaming, or
cloud deployment to M3.

**Scope**

- CI on a clean hosted runner checks Python 3.12, the committed lock, Ruff, tests,
  compilation, schema/context policy, Docker build, non-root configuration, and
  the configured vulnerability/secret scan. New gates also validate existing
  Kubernetes manifests, Helm charts, and no-backend Terraform configuration. The
  prior `main` push run passed; the expanded workflow also passed on the pushed
  feature branch ([run 39908441843](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39908441843)).
  A PR event has not yet been exercised on GitHub.
- CI never requires private dataset/model/MLflow files, trains models, or evaluates
  the final test set. It does not run a real-model inference test.
- CI and manual release actions are pinned to full commit SHAs. The manual-only
  release workflow rechecks gates and is designed to capture a digest and attach
  GitHub build provenance; this path has not been executed or verified.
- SBOM generation/retention, published-image evidence, and GHCR permission/
  attestation verification remain follow-up work. No registry push or deploy
  happens on ordinary pushes.

**Acceptance criteria**

1. A GitHub-hosted `main` push run passes lock, lint, test, compile, schema,
   context, image, non-root/content, and Trivy checks. The existing run is linked
   in the Milestone 3 report; the expanded workflow also passed on the feature
   branch as linked above. Pull-request trigger execution and branch-protection
   enforcement remain unverified.
2. CI operates without dataset/model/MLflow/cloud/Kubernetes dependencies, and no
   training or final-test scoring occurs in the job.
3. The manual release path is implemented with version validation, image scanning,
   immutable digest capture, and provenance attestation. It is intentionally
   unexecuted; GHCR permissions, publication, and attestation verification remain
   pending.
4. SBOM generation and retention are deferred and are not claimed as delivered.
5. No ordinary push publishes an image, deploys infrastructure, or runs the
   manual release workflow.

**Portfolio evidence:** workflow files, passing CI run URL, local reproduction
commands, and scan step outcome. No SBOM, published image digest, or release
attestation exists yet. Clearly mark unexercised permissions and triggers.

### M4 — Telemetry contract and generalization evidence (partially implemented)

The versioned network-event envelope, normalized HTTP ingest endpoint, synthetic
replay fixtures, idempotency, and evidence references are implemented and tested.
The API still does not accept raw Zeek logs. Define and test a Zeek-to-v1 normalizer
including `conn.log` direction, type normalization, timestamps, and DNS/TLS/HTTP/
weird joins by connection UID. Obtain a new independent collection with time/session/
device/scenario identifiers and documented permissions before claiming operational
generalization.

**Acceptance criteria:** golden fixture tests for each protocol-log mapping and
missing-field semantics; no target/identifier leakage; malformed and late/missing
joins measured; data provenance recorded; temporal and held-out-device/scenario
evaluation performed once with a preregistered protocol. The current test set remains
closed to tuning.

**Portfolio evidence:** data-flow diagram, schema/mapping specification, sanitized
fixtures, join-quality report, evaluation protocol, and independently generated
validation results with limitations.

### M5 — Identity and authorization (application implementation; deployment gate)

Generic OIDC JWT validation, role checks, tenant-scoped records, quotas, investigation
access, and cross-tenant negative tests are implemented in the application. A real
identity provider, threat model review, deployed ingress/token policy, and storage
lifecycle controls remain prerequisites to shared production access.

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

**Portfolio evidence:** identity/authz ADR, application tests, deployed-policy test,
security review record, and test output. The present implementation demonstrates
tenant-aware application isolation, not production-ready shared tenancy.

### M6 — Reliability, observability, drift, and incident operations (partially implemented)

Inference/ingestion metrics, JSON request logs, correlation IDs, sample alert rules,
a Grafana dashboard definition, configurable PSI, and analyst triage are implemented.
No alert backend, route, validated operational reference population, load test,
production runbook exercise, or incident drill has been verified. Add a separate
service only if operational ownership or scaling needs warrant it.

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

### M7 — Terraform and environment foundations (GCP validated; no apply)

Reusable GCP network/platform modules and distinct dev/prod roots are implemented.
`terraform fmt` and `terraform validate` pass using Terraform 1.17.0 with backend
initialization disabled. No project credentials or approved state bucket were
available, so no plan was generated and no resources were applied. Cost/security
review, state bucket, and deployment authorization remain required.

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
justify production Kubernetes overhead. The separate local Kind learning lab does
not satisfy this milestone and does not authorize production deployment.
The new Helm chart passes lint and template rendering for development and
production-value files. It is not installed, and it enforces one replica because
event idempotency/triage currently use SQLite.

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

### Separate infrastructure-learning track — Local Kubernetes lab

This track is intentionally separate from M4 and the ordered production/platform
milestones. It uses one local Kind cluster, the existing API image, and the
explicitly selected local XGBoost model. It does not retrain, publish an image,
provision cloud resources, or claim production Kubernetes readiness. See the
[local lab guide](local-kubernetes-lab.md), [ADR 0005](adr/0005-local-kubernetes-model-and-gitops.md),
and [design review](design-reviews/local-kubernetes-lab.md).

**Acceptance evidence:** automated manifest policy tests; restricted pod security,
no service-account token/RBAC, bounded resources and probes; real-model response
from a ready pod; invalid schema rejection; Service endpoint; successful rollout,
injected failed rollout and rollback; controller pod recreation; actual logs,
events, and resource counters. The hostPath-backed model PV is local-only and is
not a production artifact-distribution mechanism. Production artifact delivery
and GitOps remain undecided/planned as detailed in ADR 0005.

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
