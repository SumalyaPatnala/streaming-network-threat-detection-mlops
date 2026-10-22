# Streaming Network Threat Detection & MLOps Platform

Reproducible TON_IoT network-flow baselines and a versioned HTTP inference service.
The Milestone 1 metrics are research baselines only; they are not production accuracy
claims. The existing final test set was already evaluated and is **not an untouched
holdout**. Do not use it for further model selection or tuning.

## Delivery status

| Capability | Status |
|---|---|
| Reproducible training, validation, MLflow, input contract | Implemented and locally verified |
| FastAPI inference and non-root Docker image | Implemented and locally verified with a saved model |
| GitHub Actions CI and manually triggered GHCR release | Implemented; local verification recorded in the [Milestone 3 report](reports/milestone-3-report.md); hosted runs pending |
| Terraform, remote state, environment isolation | Planned; no infrastructure provisioned |
| Kubernetes worker scheduling/scaling | Future plan; not implemented |
| Streaming ingestion, drift monitoring, production observability | Future plan; not implemented |
| Authentication, authorization, multi-tenant isolation | Not implemented; this service is single-tenant/local-only |
| Incident response and reliability operations | Planned; not exercised in production |

The roadmap sequence, measurable acceptance gates, architecture decisions, and
portfolio evidence are documented in [the platform roadmap](docs/roadmap.md).
See [technical architecture](docs/architecture.md), [ADRs](docs/adr/),
and [design review records](docs/design-reviews/).

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

### CI/CD workflows

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`. It uses
Python 3.12 and the committed `uv.lock` to check dependency-lock consistency,
Ruff, pytest (JUnit XML output), compilation, the versioned input schema, Docker
context policy, the actual API image build, non-root runtime configuration, image
contents, and Trivy vulnerability/secret scanning. It has read-only repository
permissions, bounded execution, per-ref concurrency cancellation, and SHA-pinned
GitHub Actions. The JUnit XML report is retained as a short-lived workflow
artifact. Tests use the existing mocked model runtime and do not need the
local TON_IoT files, MLflow database, or saved model.

Open the repository's **Actions** tab and select **CI** to review a run. A green
hosted run is required before merging; local verification is not a substitute.
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

Endpoints:

- `GET /health/live`: process liveness.
- `GET /health/ready`: model-loaded readiness; 503 otherwise.
- `GET /v1/model/info`: selected model ID, schema, threshold, and score semantics.
- `POST /v1/predict`: one normalized record.
- `POST /v1/predict/batch`: 1–32 records.

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
