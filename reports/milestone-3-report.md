# Milestone 3: Working CI/CD Pipeline

## Outcome and status

Implemented pull-request/main-push CI and a manual-only GHCR release workflow.
The workflows are locally inspected and validated, and the API Docker image was
built locally. **GitHub-hosted workflow execution is pending** because no commit
or push was authorized. No GHCR image was published.

The ordinary workflow uses mocked model inference tests and does not require
TON_IoT data, a local MLflow database, a saved model, cloud credentials, or a
Kubernetes cluster. No model training or final-test evaluation was run.

## Files created or modified

- Created `.github/workflows/ci.yml`: pull request and `main` push CI, locked
  Python 3.12 dependencies, Ruff, pytest/JUnit output, compile, schema/context
  checks, Docker build, non-root and image-content checks, Trivy vulnerability
  and secret scan.
- Created `.github/workflows/release.yml`: manual-only release from `main`,
  stable `MAJOR.MINOR.PATCH` validation, repeated quality gates, local image
  checks and scan, fail-closed registry-tag existence check, GHCR publication,
  digest capture, published-digest pull/content checks and scan, and GitHub
  build-provenance attestation.
- Created `scripts/validate_docker_context.py`: requires private-data/secret
  ignore patterns and constrains Dockerfile `COPY` inputs to the reviewed
  application/schema/dependency allowlist.
- Modified `.dockerignore`: added key, certificate, secret, and credential
  patterns.
- Modified `.gitignore`: explicitly excludes raw/processed data, model/MLflow
  artifacts, `.venv`, test/linter/type-check caches, local secrets/credentials,
  certificates/keys, and common temporary files.
- Modified `README.md`: workflow triggers, result viewing, local reproduction,
  manual release instructions, version/digest usage, provenance verification,
  and digest-based rollback.
- Modified `docs/architecture.md` and `docs/roadmap.md` to show M3 workflows as
  implemented locally while hosted verification and publication remain pending.

No dependency manifest or lockfile changes were needed.

## Local verification

| Check | Result |
|---|---|
| Baseline `uv run pytest -q` before edits | **32 passed**, one upstream Starlette/httpx deprecation warning |
| Baseline Ruff, `uv lock --check`, Python compilation | **Passed** |
| `uv sync --locked --group dev --no-install-package nvidia-nccl-cu13` | **Passed**; avoids installing unused 305 MB Linux NCCL dependency |
| `uv run pytest -q` after implementation | **34 passed**, same upstream warning |
| `uv run ruff check src scripts tests` | **Passed** |
| `uv lock --check` | **Passed** |
| `uv run python -m compileall -q src scripts tests` | **Passed** |
| `uv run python scripts/validate_docker_context.py` | **Passed** |
| `uv run python -m json.tool schemas/network-flow-model-input-v1.schema.json` | **Passed** |
| `uv run pytest -q tests/test_model_input_schema.py` | **3 passed** |
| Exact CI `uv run --locked --no-sync` execution of lint, tests, compile, and context validation | **Passed**; 34 tests |
| Workflow YAML parsing (Ruby Psych) | Both workflow files parsed successfully |
| Workflow action reference check | All declared actions use 40-character commit SHAs |
| `git diff --check` | **Passed** |
| Private path ignore checks | `data/raw/`, `mlflow.db`, `models/`, and `.env` remain ignored |
| Docker build context observation | BuildKit transferred **835 bytes** of context; `.dockerignore` loaded as 264 bytes |
| `docker build --tag streaming-threat-api:milestone-3-ci .` | **Passed**, using cached base matching the Dockerfile's pinned digest |
| Built image identity/content check | **Passed**; configured user `app`, runtime UID 999, and no checked data/model/MLflow/secret paths |
| Local `docker build --pull` | The first attempt stalled during remote registry metadata resolution and was stopped. The successful build used the locally cached image whose `RepoDigests` matched the pinned Python base digest. |
| actionlint | **Not installed** in the environment |
| Local image vulnerability scan | **Not completed**; Trivy/Grype are not installed. Docker Scout 1.16.1 was available, but its local-image critical/high scan did not return within seven minutes and was stopped. The pinned Trivy scan remains configured in CI and release workflows. |
| GitHub-hosted CI/release | **Pending**; requires an authorized push to exercise CI |
| Image publication/provenance verification | **Not run**; release was not triggered and no image was published |

## Resolved during implementation

- An initial context-policy test import failed because `scripts/` is not on the
  project's configured pytest import path. The regression test now runs the
  validator as a subprocess, including a negative Dockerfile case; the final
  suite passes.
- The first `docker build --pull` did not finish registry metadata resolution
  locally. The required Docker image build then passed without `--pull` using
  the already cached, digest-matching base. Hosted CI still uses `--pull`.
- `git ls-remote` returned no remote refs; the public repository API reports
  `main` as the default branch. The local GitHub CLI is not authenticated.
  Hosted verification will therefore require successful authentication and
  creation/push of the first `main` commit, if no remote branch has appeared.
- A local macOS Bash version probe did not support Bash's lowercase parameter
  expansion. The release workflow uses portable `tr` for lowercase GHCR paths;
  the resulting path and stable-version validation were checked locally.

## Workflow behavior and safeguards

- CI runs for pull requests and pushes to `main`; it does not publish images. It
  has read-only repository permission, timeouts, per-ref concurrency cancellation,
  a dependency cache, and SHA-pinned external actions.
- Release requires `workflow_dispatch` on `main`, accepts stable semantic
  `MAJOR.MINOR.PATCH` values without `v`, and does not run on ordinary pushes.
- Release re-runs lock, lint, tests, compilation, schema, and Docker-context
  checks before building. It scans before publication and again by the published
  digest. Registry lookup fails closed unless the requested tag is confirmed
  absent; the workflow does not overwrite an existing version tag.
- The verified digest and source revision are written to the workflow summary;
  GitHub build provenance is generated for that digest. Operators should use
  digest references, not mutable tags, for rollback.
- CI installs the locked test environment while excluding the unused XGBoost
  NCCL package, then uses `uv run --no-sync` so commands do not silently
  resynchronize and pull that dependency.
- The Docker context policy validates required ignore rules and explicit source
  `COPY` instructions. Image checks additionally verify non-root execution and
  absence of the expected private data/model/MLflow paths.

## Security limitations and remaining work

- Workflow syntax and action pins were checked locally, but GitHub's workflow
  parser, hosted permissions, package access, vulnerability database behavior,
  and attestation publication remain unverified until hosted execution.
- `actionlint` was unavailable. Ruby YAML parsing is syntax evidence, not a
  substitute for GitHub-hosted validation or actionlint.
- Trivy is configured to ignore unfixed vulnerabilities and fail on CRITICAL/HIGH
  OS/library findings with available fixes, and to scan secrets. It has not run
  locally; a hosted scan can block CI or release until findings are remediated.
- Release requires the repository's `GITHUB_TOKEN` to have GHCR package write
  access and for the package/repository permission relationship to allow it.
- The Docker base is digest-pinned, while Python packages are pinned through
  `uv.lock`; no SBOM/signature policy or automated deployment is implemented.
- No live-model smoke test runs in CI by design. The separately documented
  Milestone 2 local real-artifact procedure remains the only such verification.
- No model accuracy/generalization claim is made. The local service remains
  unauthenticated, single-tenant, and not production-deployed.

## Commit/push decision

**NO-GO for committing or pushing in this session** because approval was not
given. Local code and image checks passed, but GitHub-hosted CI has not yet run.
After explicit approval, the first push should be treated as a CI verification
event; do not trigger the release workflow or publish an image until the hosted
CI run and package permissions have been reviewed.
