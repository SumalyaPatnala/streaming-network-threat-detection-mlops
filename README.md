# Streaming Network Threat Detection & MLOps Platform

Reproducible TON_IoT network-flow baselines and a versioned HTTP inference service.
The Milestone 1 metrics are research baselines only; they are not production accuracy
claims. The existing final test set was already evaluated and is **not an untouched
holdout**. Do not use it for further model selection or tuning.

## Delivery status

| Capability | Status |
|---|---|
| Reproducible training, validation, MLflow, input contract | Implemented and locally verified |
| MLflow registry promotion and model rollback controls | Partially implemented: experiment/artifact tracking exists and operators explicitly select an artifact; no registry-stage promotion policy or automated model rollback controller |
| FastAPI inference and non-root Docker image | Implemented and locally verified with a saved model |
| GitHub Actions CI and manually triggered GHCR release | Expanded CI passed on the pushed feature branch; manual GHCR release is implemented but intentionally unexecuted. See [the latest CI run](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39908441843) and the [Milestone 3 report](reports/milestone-3-report.md) |
| HTTP event ingestion, schema, replay, duplicate/retry handling | Implemented and locally tested for already-normalized records; raw Zeek parsing, durable broker ingestion, and live telemetry are not implemented |
| OIDC tenant identity and tenant-scoped investigations | Implemented and tested in application code; real IdP/deployed-policy verification, encryption, retention, and multi-replica state are outstanding |
| Splunk HEC prediction and triage export | Implemented behind optional HTTPS configuration and Secret-backed token; mocked tests pass; no live Splunk instance or credentials were used |
| Drift monitoring and observability | PSI monitoring is configurable; unit tests use synthetic references. No approved production baseline, Prometheus/Grafana deployment, or alert routing has been verified |
| Local Kubernetes deployment lab | Existing Kind learning lab verified before this change; it was not modified or redeployed. See the [local Kubernetes lab guide](docs/local-kubernetes-lab.md) and report |
| Helm | Development and production-value charts lint and render; no Helm release was installed |
| Terraform (GCP) | Reusable modules and dev/prod roots pass local `fmt` and `validate`; no plan or apply was run, and no infrastructure is deployed |
| Production Kubernetes, worker scheduling/scaling, and GitOps | Not externally verified; one replica is required while the event store is SQLite |
| Incident response | Deterministic analyst-review recommendation and tenant-scoped human triage are implemented; no disruptive response action is automated |

The roadmap sequence, measurable acceptance gates, architecture decisions, and
portfolio evidence are documented in [the platform roadmap](docs/roadmap.md).
See [technical architecture](docs/architecture.md), [ADRs](docs/adr/),
and [design review records](docs/design-reviews/).

## Resume-claim implementation matrix

| Resume claim | Code and configuration | Verification evidence | Status |
|---|---|---|---|
| Containerized ML services and real-time inference | [`Dockerfile`](Dockerfile), [`src/threat_detection/api.py`](src/threat_detection/api.py), [`tests/test_api.py`](tests/test_api.py) | Local saved-model Docker inference was recorded in the Milestone 2 and local Kubernetes reports; latest image build and non-root import smoke pass | Implemented and verified locally |
| Streaming network-event ingestion | [`schemas/network-security-event-v1.schema.json`](schemas/network-security-event-v1.schema.json), [`src/threat_detection/event_store.py`](src/threat_detection/event_store.py), [`src/threat_detection/replay.py`](src/threat_detection/replay.py) | Versioned normalized records, idempotency/conflict tests, auth tests, and synthetic replay fixtures pass; raw Zeek parsing and durable brokers are absent | Implemented and verified for normalized HTTP events |
| Automation, CI/CD, image build, release controls | [`.github/workflows/ci.yml`](.github/workflows/ci.yml), [`.github/workflows/release.yml`](.github/workflows/release.yml), [`scripts/`](scripts/) | [Expanded hosted push CI passed](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39908441843), including tests, Helm/Terraform, image build, Trivy vulnerability/secret scan; manual image release was not triggered | Implemented and verified for CI; release unverified |
| Drift monitoring, Prometheus/Grafana, operational alerts | [`src/threat_detection/drift.py`](src/threat_detection/drift.py), [`src/threat_detection/observability.py`](src/threat_detection/observability.py), [`deploy/observability/`](deploy/observability/) | PSI, metric, and alert-definition tests pass against synthetic inputs; no approved reference population, deployed Prometheus/Grafana, or live alert route | Implemented; external monitoring unverified |
| Splunk predictions, investigation events, and dashboards | [`src/threat_detection/splunk.py`](src/threat_detection/splunk.py), [`deploy/splunk/`](deploy/splunk/), [`tests/test_ingestion.py`](tests/test_ingestion.py) | HEC payload and failure behavior are mocked and tested; Simple XML parses. No live Splunk search, import, or alert route was tested | Implemented but not externally verified |
| MLflow experiments, artifacts, evaluation, promotion, and rollback | Existing [`scripts/train_baselines.py`](scripts/train_baselines.py), [`src/threat_detection/api.py`](src/threat_detection/api.py), and saved artifact selection | Existing experiment/artifact workflow is reused; inference is tied to an explicit model artifact. There is no registered-model promotion policy or automated model rollback | Partially implemented |
| Kubernetes orchestration and Helm | [`deploy/helm/threat-detection/`](deploy/helm/threat-detection/), [`docs/local-kubernetes-lab.md`](docs/local-kubernetes-lab.md) | Helm lint and dev/prod template rendering pass; existing Kind lab has prior real-model evidence, but this chart/image was not installed or redeployed | Implemented; updated deployment unverified |
| Terraform cloud infrastructure | [`infra/terraform/`](infra/terraform/) | Terraform 1.17.0 `fmt -check` and `validate` pass for dev/prod; no credentialed plan or apply; infrastructure is not deployed | Implemented and locally validated |
| Tenant isolation and human incident workflow | [`src/threat_detection/identity.py`](src/threat_detection/identity.py), [`src/threat_detection/event_store.py`](src/threat_detection/event_store.py), [`tests/test_identity.py`](tests/test_identity.py), [`tests/test_ingestion.py`](tests/test_ingestion.py) | Signed-token, role, tenant-scoping, and cross-tenant negative tests pass; persistent state is single-process SQLite and no real IdP/deployed policy was verified | Implemented and application-tested |

## Environment and tests

```bash
uv sync
uv run pytest
uv run ruff check src scripts tests
uv lock --check
uv run python -m compileall -q src scripts tests
uv run python scripts/validate_docker_context.py
uv run python -m json.tool schemas/network-flow-model-input-v1.schema.json > /dev/null
uv run pytest -q tests/test_model_input_schema.py
docker build --pull --tag streaming-threat-api:ci .
docker run --rm --entrypoint python streaming-threat-api:ci -c \
  'import os; assert os.getuid() != 0'
```

Latest local validation: **73 pytest tests passed** with one upstream
Starlette/httpx deprecation warning; Ruff, `uv lock --check`, and Python
compilation passed. Helm lint/rendering passed for development and production
values. Terraform 1.17.0 `fmt -check` and `validate` passed for both environments.
The Docker image rebuilt and imported the application as non-root; JSON, YAML,
XML, Kubernetes manifest, and Docker-context checks passed. The
[expanded hosted CI run](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39908441843)
also passed. These checks do not constitute live Splunk, an updated cluster
deployment, or cloud infrastructure verification.

### CI/CD workflows

`.github/workflows/ci.yml` runs on pull requests and pushes to all branches. It uses
Python 3.12 and the committed `uv.lock` to check dependency-lock consistency,
Ruff, pytest (JUnit XML output), compilation, the versioned input schema, Docker
context policy, the actual API image build, non-root runtime configuration, image
contents, and Trivy vulnerability/secret scanning. It has read-only repository
permissions, bounded execution, per-ref concurrency cancellation, and SHA-pinned
GitHub Actions. The JUnit XML report is retained as a short-lived workflow
artifact. Tests use the existing mocked model runtime and do not need the
local TON_IoT files, MLflow database, or saved model.

The first hosted push run passed on commit `e8ef1c93adb7bb94b504de346e3f81e9242d56fe`:
[view GitHub Actions CI run](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39811616149).
Open the repository's **Actions** tab and select **CI** to review future runs;
local verification is not a substitute for hosted checks.
The existing real-model inference smoke test remains a separate local procedure
in the [Milestone 2 report](reports/milestone-2-report.md).

### Manual GHCR release

No push to `main` publishes an image. To release, open **Actions → Release → Run
workflow**, select `main` under **Use workflow from**, enter a stable semantic
version without a leading `v` (for example, `1.2.3`), and start the workflow. It re-runs the quality gates, builds and scans
the image, checks that `v1.2.3` has not already been published, then pushes the
version tag to `ghcr.io/sumalyapatnala/streaming-network-threat-detection-mlops`.
It captures the registry digest, verifies the pulled published image, scans that
digest, and creates a GitHub build-provenance attestation. The workflow requires
GHCR package write access and does not provision cloud infrastructure.

The version tag is for discovery; deploy or run an image by its immutable digest
from the successful release run's summary:

```bash
docker pull ghcr.io/sumalyapatnala/streaming-network-threat-detection-mlops@sha256:<digest>
docker run --rm \
  --memory=1g --cpus=1 \
  -e MODEL_ID=<approved-model-id> \
  -v /trusted/model/path:/models/xgboost:ro \
  ghcr.io/sumalyapatnala/streaming-network-threat-detection-mlops@sha256:<digest>
```

Verify provenance with a recent GitHub CLI:

```bash
gh attestation verify oci://ghcr.io/sumalyapatnala/streaming-network-threat-detection-mlops@sha256:<digest> \
  --owner SumalyaPatnala
```

For rollback, select a previously verified digest from a successful release
summary, verify its attestation, then pin the runtime to
`ghcr.io/sumalyapatnala/streaming-network-threat-detection-mlops@sha256:<digest>`.
Do not rely on a mutable tag for rollback. This local platform has no automated
deployment or rollback controller.

### Local Kubernetes learning lab

The local Kind lab is separate from roadmap milestone M4 (telemetry contract and
generalization evidence). It reuses the local Docker image and explicitly selected
saved model; it does not retrain, publish, or embed model files. Follow the
[lab guide](docs/local-kubernetes-lab.md) for prerequisites, startup, real-model
inference, failure injection, and cleanup. Its host-mounted model PV is strictly
for local learning and is not a production artifact-distribution design. No cloud
resources or GHCR publication are involved.

The original audit can be rerun without changing raw data:

```bash
uv run python scripts/audit_dataset.py
```

Training and model comparison use the training and validation partitions only:

```bash
uv run python scripts/train_baselines.py
```

Final test scoring is disabled by default. `--evaluate-final-test` is an explicit,
documented switch for an auditable final evaluation; this option must not be used
for ordinary training/comparison or to tune/select models. The current test set has
already been evaluated, so additional scoring does not restore an independent holdout.

## Local inference

Select a trusted, completed XGBoost MLflow model artifact explicitly. The existing
locally saved artifact used for Milestone 2 is
`m-e938dbe02eac44609ef11145e7eaa535`. The model directory is ignored by Git:

```bash
mkdir -p models/xgboost
cp -R mlruns/1/models/m-e938dbe02eac44609ef11145e7eaa535/artifacts/. models/xgboost/
MODEL_PATH="$PWD/models/xgboost" \
MODEL_ID="m-e938dbe02eac44609ef11145e7eaa535" \
uv run uvicorn threat_detection.api:app --app-dir src --host 127.0.0.1 --port 8000
```

The service requires both `MODEL_PATH` and `MODEL_ID`; startup fails explicitly if
the artifact or the v1 schema is missing/incompatible. `MODEL_SCHEMA_PATH` can
override the bundled schema location. The process loads the fitted pipeline once
during startup. It does not parse raw Zeek logs or join Zeek protocol logs: callers
must send already-normalized records that conform to
[schema v1](schemas/network-flow-model-input-v1.schema.json).

The training and evaluation scripts log reproducible runs and model artifacts to
MLflow. Serving requires an explicit `MODEL_PATH` and `MODEL_ID`; there is no
registered-model alias, automated promotion gate, or model rollback controller.
An operator can select a previously verified artifact and roll the deployment
back manually, but that workflow has not been automated or tested against a live
registry.

Endpoints:

- `GET /health/live`: process liveness.
- `GET /health/ready`: model-loaded readiness; 503 otherwise.
- `GET /v1/model/info`: selected model ID, schema, threshold, and score semantics.
- `POST /v1/predict`: one normalized record.
- `POST /v1/predict/batch`: 1–32 records.
- `POST /v1/ingest`: 1–32 authenticated, versioned events with evidence references.
- `GET /v1/events/{event_id}` and `GET /v1/incidents`: tenant-scoped investigations.
- `POST /v1/incidents/{event_id}/triage`: analyst acknowledgment or dismissal.
- `GET /v1/monitoring/drift`: tenant-scoped status when a reference is configured.
- `GET /metrics`: Prometheus exposition format.

The classification threshold is **0.5**. `model_score` is the XGBoost model's
uncalibrated positive-class probability—not calibrated threat risk. Input objects
must include all 30 feature names; individual values can be `null`. Unknown,
missing, extra, or wrong-typed fields are rejected. Payloads are capped at 256 KiB.

### Sanitized request

```json
{
  "schema_version": "1.0.0",
  "event_id": "container-smoke-001",
  "observed_at": "2026-10-22T12:00:00Z",
  "features": {
    "dst_port": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.12,
    "src_bytes": 128,
    "dst_bytes": 512,
    "conn_state": "SF",
    "missed_bytes": 0,
    "src_pkts": 3,
    "src_ip_bytes": 260,
    "dst_pkts": 4,
    "dst_ip_bytes": 672,
    "dns_qclass": null,
    "dns_qtype": null,
    "dns_rcode": null,
    "dns_AA": null,
    "dns_RD": null,
    "dns_RA": null,
    "dns_rejected": null,
    "ssl_version": "TLSv13",
    "ssl_cipher": "TLS_AES_128_GCM_SHA256",
    "ssl_resumed": "F",
    "ssl_established": "T",
    "http_trans_depth": null,
    "http_method": null,
    "http_version": null,
    "http_request_body_len": 0,
    "http_response_body_len": 0,
    "http_status_code": 0,
    "weird_notice": null
  }
}
```

### Sanitized response shape

```json
{
  "event_id": "container-smoke-001",
  "observed_at": "2026-10-22T12:00:00Z",
  "prediction": 0,
  "class_label": "normal",
  "model_score": 0.023613212630152702,
  "threshold": 0.5,
  "model_id": "m-e938dbe02eac44609ef11145e7eaa535",
  "schema_version": "1.0.0"
}
```

This is the actual response from a sanitized synthetic request sent to the local
Docker container with the selected saved model. It is an inference example, not
telemetry-grounded evidence or a production-performance claim.

## Streaming ingestion, tenant identity, and incident triage

`POST /v1/ingest` is a bounded, near-real-time HTTP ingestion path for events that
have already been normalized to the 30-feature v1 contract. Event envelopes use
[network event schema v1](schemas/network-security-event-v1.schema.json) and
include `event_id`, timezone-aware `observed_at`, feature values, and one or more
evidence references. The API does not parse raw Zeek logs, perform connection-UID
joins, or claim a Kafka/Splunk input stream.
Evidence references are caller-supplied trace labels; the service does not
dereference or cryptographically validate the underlying source records.

The API requires a verified OIDC bearer token for ingestion and investigation.
Configure `OIDC_ISSUER`, `OIDC_AUDIENCE`, and HTTPS `OIDC_JWKS_URL`; tokens must
carry `sub`, `tenant_id`, and a non-empty `roles` array. `tenant_id` is derived
from verified claims and caller-provided tenant fields are rejected. `events:write`
or `admin` may ingest; `analyst` or `admin` may read/triage incidents. When OIDC
is absent, legacy local prediction remains single-tenant, while tenant ingestion
fails closed with HTTP 503. Health and metrics endpoints remain unauthenticated;
keep them on a trusted network.

For local replay, first run the API with an explicitly selected model, configure
the OIDC values for a trusted test identity provider, and load the access token
into `THREAT_API_TOKEN` from a secure local secret source. The sample events contain
synthetic values only:

```bash
export THREAT_API_URL=http://127.0.0.1:8000
read -s THREAT_API_TOKEN
export THREAT_API_TOKEN
uv run python scripts/replay_events.py
unset THREAT_API_TOKEN
```

The replay script sends only to HTTPS or loopback HTTP, uses the bearer token in an
authorization header, and never prints the token. Replaying an unchanged event
returns its prior prediction; reusing an event ID with changed content returns 409.
SQLite keys are `(tenant_id, event_id)`. The optional `EVENT_STORE_PATH` persists
prediction metadata, evidence references, and triage decisions with restrictive
file permissions; raw feature payloads are not stored. The default is in-memory.
SQLite is single-process and not multi-replica safe. The process-local rate limit
is 120 events per tenant per minute and resets on restart. Batch records are
committed one at a time: if a later inference or integration step fails, earlier
records may already be stored. Retrying the same batch is safe for stored
predictions because event IDs and content digests make ingestion idempotent.

An attack classification creates an `analyst_review` recommendation, not an
automated response. An analyst must explicitly acknowledge or dismiss the
investigation. No host isolation, account suspension, network blocking, or other
disruptive action is implemented.

## Splunk, drift, and observability

When `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` are configured, the service sends
structured prediction/evidence events and analyst-triage events over HTTPS to
Splunk HEC. Searches and a Simple XML dashboard are provided in
[`deploy/splunk/`](deploy/splunk/). Set the dashboard's index token to the index
configured in `SPLUNK_INDEX` (or the Splunk default). Events distinguish
`model_prediction` from `incident_triage`; both include tenant, event, and
evidence references. The token should
come from a secret manager or Kubernetes Secret; it is never part of a request,
metric label, or log. HEC delivery is at-least-once: the SQLite outbox retries
failed delivery on a repeated event, but a crash after Splunk accepts an event and
before the local acknowledgment may produce a duplicate. Prediction delivery has
a persisted retry state; triage delivery is synchronous, and a repeated triage
request can create duplicate Splunk audit events after an ambiguous failure.
HEC behavior is tested with a mock; live Splunk search, dashboard import,
credentials, and alert routing have not been exercised.

Feature drift uses population stability index (PSI) against a separately supplied,
operator-validated reference file matching
[reference schema v1](schemas/feature-drift-reference-v1.schema.json). Configure
`DRIFT_REFERENCE_PATH`, `DRIFT_PSI_THRESHOLD` (default 0.2), and
`DRIFT_WINDOW_SIZE` (default 100 valid feature values). No reference baseline is
bundled: the source data does not establish an approved operational population.
Without a baseline, the API reports `not_configured`; tests use synthetic
distributions and do not constitute production drift evidence. The current monitor
keeps per-tenant in-memory windows and publishes aggregate feature-only metrics.

`/metrics` exposes inference outcomes/latency, ingestion errors and outcomes,
Splunk delivery failures, and configured feature drift. Example
[Prometheus alert rules](deploy/observability/prometheus-alerts.yaml) and a
[Grafana dashboard](deploy/observability/grafana-dashboard.json) are provided,
but they have not been installed, connected to a Prometheus data source, or
validated with live alerts. Request logs use JSON with correlation IDs and omit
request bodies, bearer tokens, and tenant identifiers.

## Helm and GCP Terraform

Validate Kubernetes/Helm without installing a release:

```bash
uv run python scripts/validate_k8s_manifests.py
bash scripts/validate_helm.sh
```

The chart has development and production values, non-root/read-only runtime
controls, probes, resource bounds, model and event-store volume references,
optional OIDC and Splunk Secret references, and an optional drift-reference
ConfigMap mount. It deliberately rejects multiple replicas while SQLite is used.
The local Kind deployment predates this chart; no release was installed as part of
this change.

The [GCP Terraform configuration](infra/terraform/) includes private network,
Autopilot GKE, Artifact Registry, a private versioned model bucket, and a
least-privilege Workload Identity binding. It is validated configuration, **not
deployed infrastructure**. No credentials, plans, or cloud resources were used.
The GCS backend bucket must be pre-created and approved. Plan review, model
artifact download wiring, and apply approval remain outstanding.

## Docker

BuildKit Docker build uses the locked `uv.lock`, Python 3.12 slim, and the XGBoost
OpenMP runtime. The image runs as a non-root user and excludes data, local MLflow
stores, reports, tests, and model files. Mount an explicitly selected trusted
MLflow model directory read-only at `/models/xgboost`:

```bash
docker build -t streaming-threat-api:local .
docker run --rm \
  --memory=1g --cpus=1 \
  -p 8000:8000 \
  -e MODEL_ID=m-e938dbe02eac44609ef11145e7eaa535 \
  -v "$PWD/models/xgboost:/models/xgboost:ro" \
  streaming-threat-api:local
```

See [the architecture and operating notes](docs/architecture.md) for runtime
boundaries and the Milestone 2 report for executed verification results.

## Current limitations

The source TON_IoT collection has no session, timestamp, device, or scenario keys.
Its random grouped split does not establish temporal/testbed independence, and the
existing test scores are not evidence of production generalization. Live feature
normalization and Zeek log joins are not part of this service; the API only accepts
the versioned normalized feature contract.
