# Milestone 5 — End-to-End Local Demo

## Scope and boundaries

This guide reproduces the saved-model application integration and the updated
Helm release in the project's dedicated local Kind cluster. It does not deploy
cloud resources or change `main`.

The application-level integration test loads the existing ignored MLflow
artifact, verifies signed synthetic JWT claims and role/tenant boundaries,
exercises the real HTTPS Splunk HEC client against a local TLS mock, triggers a
synthetic PSI alert, and performs human triage. The JWKS lookup is stubbed to
return the test public key; the signature, issuer, audience, expiry, tenant, and
role claims are verified by the production OIDC verifier. The local HEC
certificate is explicitly trusted only by the test client.

The Kind Helm release uses the actual saved model and exposes inference and
metrics. It does **not** configure OIDC or Splunk, so tenant endpoints fail
closed and Splunk is not exported from the pod. Prometheus/Grafana are separate
local Docker Compose services; no production monitoring stack or IdP is deployed.
Terraform is validation-only, with no plan/apply.

## Prerequisites

- Python environment installed with `uv sync`.
- Existing selected model copied to ignored `models/xgboost/`, containing
  `MLmodel` and `model.pkl`. Never add it to Git or the image.
- For the Kubernetes demo: Docker, Kind, kubectl, and Helm; the pre-existing
  `network-threat-lab` cluster and the read-only `network-threat-model` PVC.
  The scripts refuse to create another cluster or target other Kind clusters.
- For the metrics-stack demo: Docker Compose and free loopback ports 18081,
  19090, and 13000.

## Run saved-model end-to-end app test

```bash
scripts/demo_end_to_end.sh
```

The test runs an actual FastAPI `TestClient` with the saved model, creates
short-lived signed tenant JWTs, and starts a local HTTPS mock HEC with an
ephemeral test certificate. It submits an attack-classified synthetic event,
simulates a temporary HEC 503 and retries the same event, verifies no
reinference for the duplicate, rejects a malformed schema and conflicting
event-ID reuse, runs batch inference, triggers a synthetic drift alert, denies
cross-tenant reads and unauthorized triage, records analyst history, exports
prediction/triage evidence, and parses `/metrics`.

`MODEL_PATH` may point to another compatible trusted local MLflow artifact.
Synthetic drift reference values validate the alerting mechanism only; they are
not an approved operational baseline. The test-only HEC token and TLS key stay
in the test process/temp directory and are never committed or logged.

## Deploy and verify the Helm release in Kind

```bash
scripts/deploy_kind_helm.sh
scripts/verify_kind_helm.sh
```

These scripts target only `kind-network-threat-lab` and the repository-owned
`threat-detection-lab` namespace. They verify namespace ownership, the existing
read-only model PVC and node mount, build and load `streaming-threat-api:m5-local`,
and install/upgrade the separate `m5-platform` Helm release. The pre-existing
`network-threat-api` Deployment is left untouched.

The smoke test reports the live probe configuration and successful startup and
readiness, verifies UID 999 and denied model writes, checks `/health/live` and
`/health/ready`, sends real saved-model single and batch predictions, verifies
HTTP 422 for an unsupported schema, verifies tenant ingestion returns HTTP 503
while OIDC is intentionally unconfigured, and parses `/metrics` as Prometheus
text including the model identity and model-labeled inference counter.

The smoke script uses local port 18081 for a short-lived port-forward and stops
it on exit. Do not run it if another process is already using that port.

## Optional local Prometheus and Grafana

With the Helm service deployed, start a local-only port-forward in one terminal:

```bash
kubectl --context kind-network-threat-lab \
  --namespace threat-detection-lab \
  port-forward service/m5-platform-threat-detection 18081:8000
```

In another terminal, set a throwaway local Grafana password and start the
isolated monitoring project:

```bash
export GRAFANA_ADMIN_PASSWORD='replace-with-a-local-only-password'
docker compose -p threat-detection-m5 \
  -f deploy/observability/docker-compose.yml up -d
```

Prometheus is bound to `127.0.0.1:19090` and scrapes the API through
`host.docker.internal:18081`. The Compose configuration loads the checked-in
alert rules, provisions the Prometheus datasource and dashboard, uses
loopback-only published ports, and does not contain a committed password.
Grafana is at `http://127.0.0.1:13000` (`admin` plus the password supplied in
the environment). Stop only these named local services when finished:

```bash
docker compose -p threat-detection-m5 \
  -f deploy/observability/docker-compose.yml down --volumes
```

Stop the port-forward with Ctrl-C. This does not remove the Kind Helm release.

## Recorded verification

- **Kind:** cluster `network-threat-lab`, namespace `threat-detection-lab`,
  Helm release `m5-platform`, image `streaming-threat-api:m5-local`.
- **Runtime:** 1/1 pod ready, successful startup/readiness probes, liveness
  endpoint HTTP 200, process UID 999, model volume read-only, root filesystem
  read-only, capabilities dropped, service-account token absent.
- **Inference:** actual selected model
  `m-e938dbe02eac44609ef11145e7eaa535`; sanitized sample returned class
  `normal`, score `0.023613212630152702`, threshold `0.5`, schema `1.0.0`.
  The model score is an **uncalibrated** model output, not a risk probability.
- **API smoke:** batch returned 2 predictions; unsupported schema returned 422;
  tenant ingestion returned 503 because the Helm release has no OIDC identity
  provider configuration.
- **Metrics:** `/metrics` parsed successfully into 22 Prometheus metric
  families. Model identity and model-labeled inference counters were present;
  tenant IDs are not exposed as metric labels.
- **Saved-model application integration:** one dedicated end-to-end test passes.
  It verifies signed JWT claim checks, role restrictions, cross-tenant
  isolation, idempotency/conflict handling, actual inference, batch inference,
  local HTTPS HEC 503/retry and prediction/triage payloads, synthetic drift
  alerting, triage history, and metrics.
- **Prometheus/Grafana local run:** Prometheus became ready and scraped the API
  with query result `up{job="threat-detection-api"} = 1`; it loaded the four
  rules `ThreatDetectionInferenceErrors`, `ThreatDetectionIngestionErrors`,
  `ThreatDetectionFeatureDrift`, and `ThreatDetectionSplunkDeliveryErrors` with
  health `ok`. Grafana reported database health `ok` and served the
  `network-threat-detection` four-panel dashboard.
- **Regression and configuration gates:** `75 passed` in `pytest -q` (one
  upstream Starlette/httpx deprecation warning); the dedicated
  `scripts/demo_end_to_end.sh` run passed. Ruff, `uv lock --check`, Python
  compilation, Kubernetes manifest/security policy, Docker-context policy,
  development/production Helm lint and rendering, Compose config parsing, and
  `git diff --check` passed.
- **Terraform:** dev/prod `fmt -check` and `validate` only; backend disabled;
  Terraform 1.17.0 initialized with `-backend=false`; dev/prod validate
  successfully. No cloud plan or apply.
- **Limitations:** no live Splunk, real IdP/JWKS endpoint, production drift
  baseline, cloud plan/apply, public image release, or production Kubernetes
  deployment. The existing local host-backed model PV is not a production
  artifact-distribution design. SQLite is single-process/single-replica only.

Run the Python regression suite with `uv run --locked pytest -q`. The saved-model
test is skipped automatically on CI or clean workstations that do not have the
ignored artifact.
