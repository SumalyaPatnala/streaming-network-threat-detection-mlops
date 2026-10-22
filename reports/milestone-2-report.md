# Milestone 2: Production-Oriented Model Serving

## Outcome

Implemented and locally verified a versioned FastAPI service and Docker image using the existing saved MLflow XGBoost pipeline. This milestone does **not** establish production detection accuracy or deployment readiness. The dataset's scenario/testbed generalization limitations remain as described in [the Milestone 1 readiness review](./milestone-1-readiness.md).

No model was retrained and no final-test row was scored during this milestone. The existing test set was already evaluated in Milestone 1 and must not be treated as an untouched holdout.

## Test-set governance

- `scripts/train_baselines.py` does not access `indices["test"]`, compute test metrics, or log test metrics by default. Candidate ranking remains validation PR-AUC.
- Final test evaluation requires the explicit `--evaluate-final-test` CLI switch. Help text documents that the test set was already evaluated and this option is for audit/reporting, not ordinary comparison or tuning.
- When explicitly enabled, test metrics are computed and logged separately for reporting; the option was **not** run during this milestone.
- `tests/test_training_governance.py` confirms the shared gate does not call a predictor when disabled and does evaluate when explicitly enabled.

## API and input contract

- Added FastAPI endpoints: `GET /health/live`, `GET /health/ready`, `GET /v1/model/info`, `POST /v1/predict`, and `POST /v1/predict/batch`.
- The service loads an explicitly selected local MLflow artifact once in application lifespan. Startup verifies the v1 schema, all 30 feature names/order, a fitted preprocessing/classifier pipeline, XGBoost model type, and binary classes. Missing settings, model artifacts, or schemas fail startup explicitly.
- Pydantic enforces schema version `1.0.0`, exactly the schema's 30 typed feature keys, nullability, no extra fields, timestamp timezone, numeric constraints, strict types, batch length 1–32, and an HTTP request-body cap of 256 KiB.
- Shared `PredictionService` keeps record inference reusable outside HTTP. The API accepts normalized contract records only; it does not parse Zeek logs or silently perform joins/coercions.
- The classification threshold is **0.5**. `model_score` is an **uncalibrated positive-class model probability**, not calibrated threat risk.
- The selected local artifact is `m-e938dbe02eac44609ef11145e7eaa535`. It is mounted from ignored `models/xgboost/` at runtime, never copied into the image. Cloudpickle artifacts must only be loaded from a trusted source.

## Container

- Built `streaming-threat-api:milestone-2` successfully with the locked Python dependencies, a Python 3.12 slim base, XGBoost OpenMP runtime, and a non-root `app` user.
- Pinned the Python base by digest and omitted the optional NCCL runtime unused by this CPU-only, single-process inference image. The final image is **1,050,113,893 bytes** (about 1.05 GB decimal).
- `.dockerignore` excludes datasets, MLflow stores, local model directories, secrets, tests, reports, and training scripts. The runtime model is mounted read-only.
- Docker health check uses `/health/ready`. The smoke container ran with the documented 1 GiB memory and 1 CPU limit.
- Docker build initially blocked while resolving remote BuildKit/uv registry images. Switched to the already available Python slim base and installed the pinned uv version from the package index; the final build completed successfully.

## Executed verification

| Check | Result |
|---|---|
| `uv run pytest -q` | **32 passed** |
| `uv run ruff check src scripts tests` | **Passed** |
| `uv lock --check` | **Passed** |
| `uv run python -m compileall -q src/threat_detection scripts/train_baselines.py tests` | **Passed** |
| `git diff --check` | **Passed** |
| `uv run python scripts/train_baselines.py --help` | Verified explicit test-evaluation option and warning |
| `docker build --tag streaming-threat-api:milestone-2 .` | **Passed** |
| Saved artifact direct load + `PredictionService` inference | **Passed** using the selected actual MLflow artifact and a synthetic contract-shaped record |
| Docker readiness, health, model info, single prediction, batch prediction, invalid schema | **Passed** using the selected actual saved model |
| Container identity/resource inspection | `user=app`, memory `1,073,741,824` bytes, CPU `1,000,000,000` nano-CPUs |
| Test-set training/evaluation | **Not run** |

The real-model synthetic request returned prediction `0` (`normal`), score `0.023613212630152702`, threshold `0.5`, model ID `m-e938dbe02eac44609ef11145e7eaa535`, schema version `1.0.0`. Repeating the request returned the same output. This is a smoke-test output only; it is not a labeled evaluation or a model-quality claim. A schema-version mismatch returned HTTP 422. A valid two-record batch returned two predictions.

The first API test run found strict JSON datetime parsing and test-fixture type-name assumptions; both were corrected. An initial container smoke request used a single-record body at the batch endpoint and correctly received 422; after correcting the batch envelope, it returned two predictions. The final test run passed all 32 tests with one upstream Starlette deprecation warning about the installed `httpx` integration. Ruff initially reported two issues in the existing dataset-audit script; both small import/iteration issues were corrected, after which the full configured Ruff check passed.

## Reproduction commands

```bash
uv sync
uv run pytest -q
uv run ruff check src scripts tests
uv run python scripts/train_baselines.py --help

# Stage the already-saved, explicitly selected local artifact (ignored by Git).
mkdir -p models/xgboost
cp -R mlruns/1/models/m-e938dbe02eac44609ef11145e7eaa535/artifacts/. models/xgboost/

docker build --tag streaming-threat-api:milestone-2 .
docker run --rm \
  --memory=1g --cpus=1 \
  -p 8000:8000 \
  -e MODEL_ID=m-e938dbe02eac44609ef11145e7eaa535 \
  -v "$PWD/models/xgboost:/models/xgboost:ro" \
  streaming-threat-api:milestone-2
```

Do not invoke `--evaluate-final-test` for routine training, comparison, or tuning.

## Remaining limitations and risks

- Existing near-perfect Milestone 1 scores remain vulnerable to scenario, testbed, host-role, and collection-period correlations. The source CSV has no timestamp, session, device, or scenario identifier. The service is not production validated.
- Several features require correctly correlated Zeek `dns.log`, `ssl.log`, `http.log`, or `weird.log` data. This service requires callers to provide the normalized 30-feature record and does not verify upstream extraction semantics.
- The model has no calibrated threat-risk interpretation; the 0.5 decision threshold is a baseline convention, not an operational policy.
- Authentication, authorization, TLS termination, rate limiting beyond batch/body limits, remote artifact registry integration, and distributed serving are out of scope. Keep the service on a trusted local network until those are addressed.
- No Kafka, Kubernetes, Argo CD, or cloud deployment was implemented. A new independently collected temporal/device/testbed evaluation and an explicit threshold policy remain prerequisites for any production claim.
