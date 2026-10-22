# Milestone 3: Working CI/CD Pipeline

## Outcome and status

Implemented pull-request/main-push CI and a manual-only GHCR release workflow.
The first GitHub-hosted CI run passed on `main`. The manual GHCR release workflow
is implemented but was not triggered; no image was published. CI verification is
complete for the hosted `push` event. A pull-request event and the release
publication/provenance path remain unverified.

- **Run:** [CI run 39811616149](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39811616149)
- **Commit:** `e8ef1c93adb7bb94b504de346e3f81e9242d56fe`
- **Trigger:** push to `main`
- **Conclusion:** success

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
- Modified `docs/architecture.md` and `docs/roadmap.md` to record hosted CI
  success and distinguish it from the unexecuted release path.

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
| Common secret/cache/temp ignore checks | `.aws/`, `.ssh/`, credential/key/certificate files, `.venv`, pytest/Ruff/mypy caches, and temp/log files all match Git ignore rules |
| Docker build context observation | BuildKit transferred **835 bytes** of context; `.dockerignore` loaded as 264 bytes |
| `docker build --tag streaming-threat-api:milestone-3-ci .` | **Passed**, using cached base matching the Dockerfile's pinned digest |
| Built image identity/content check | **Passed**; configured user `app`, runtime UID 999, and no checked data/model/MLflow/secret paths |
| Local `docker build --pull` | The first attempt stalled during remote registry metadata resolution and was stopped. The successful build used the locally cached image whose `RepoDigests` matched the pinned Python base digest. |
| actionlint | **Not installed** in the environment |
| Local image vulnerability scan | **Not completed**; Trivy/Grype are not installed. Docker Scout 1.16.1 was available, but its local-image critical/high scan did not return within seven minutes and was stopped. The pinned Trivy scan remains configured in CI and release workflows. |
| GitHub-hosted CI | **Passed** on push to `main`; run `39811616149`, commit `e8ef1c93adb7bb94b504de346e3f81e9242d56fe` |
| Image publication/provenance verification | **Not run**; release was not triggered and no image was published |

## GitHub-hosted verification

The GitHub-hosted run
[39811616149](https://github.com/SumalyaPatnala/streaming-network-threat-detection-mlops/actions/runs/39811616149)
completed successfully on `main` for commit
`e8ef1c93adb7bb94b504de346e3f81e9242d56fe` (push event, 2026-10-22
16:09:57–16:11:32 UTC). The `Quality, image, and security checks` job and every
reported step concluded `success`, including dependency installation, Ruff, pytest,
JUnit report upload, compilation, schema/context checks, Docker build, non-root and
private-content checks, and Trivy vulnerability/secret scanning.

The public Actions API exposed per-step conclusions but did not provide the job
logs (`403 Must have admin rights to Repository`), so the hosted test count is not
independently recorded here. The local run on this same source passed **34 tests**.
Trivy's configured scan passed; it ignores unfixed vulnerabilities and gates on
CRITICAL/HIGH vulnerabilities with fixes plus secret findings. This is not a claim
that the image has zero vulnerabilities.

The `push` trigger is verified; a pull-request event has not been exercised.
The manual release workflow was not triggered, and GHCR publication, package
permissions, registry digest capture, and provenance attestation were not verified.

## Resolved during implementation

- An initial context-policy test import failed because `scripts/` is not on the
  project's configured pytest import path. The regression test now runs the
  validator as a subprocess, including a negative Dockerfile case; the final
  suite passes.
- The first `docker build --pull` did not finish registry metadata resolution
  locally. The required Docker image build then passed without `--pull` using
  the already cached, digest-matching base. Hosted CI still uses `--pull`.
- Before the first push, `git ls-remote` returned no remote refs while the public
  repository API reported `main` as the default branch. The initial commit created
  `main` successfully. `gh auth status` is not authenticated, but the normal Git
  push succeeded through the configured macOS credential helper.
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

- The GitHub-hosted push run validated the CI workflow parser, its read-only
  permissions, dependency installation, image build, and configured Trivy scan.
  The pull-request trigger remains unexercised.
- `actionlint` was unavailable. Ruby YAML parsing is syntax evidence, not a
  substitute for GitHub-hosted validation or actionlint.
- The hosted Trivy scan passed with the workflow's policy: ignore unfixed
  vulnerabilities, fail on CRITICAL/HIGH OS/library findings with available
  fixes, and scan secrets. It is not evidence of zero vulnerabilities.
- Release requires the repository's `GITHUB_TOKEN` to have GHCR package write
  access and for the package/repository permission relationship to allow it; this
  was not tested because publication was not run.
- The Docker base is digest-pinned, while Python packages are pinned through
  `uv.lock`; SBOM generation/retention and automated deployment are not implemented.
- GitHub build provenance is configured in the release workflow but no attestation
  has been generated or verified.
- No live-model smoke test runs in CI by design. The separately documented
  Milestone 2 local real-artifact procedure remains the only such verification.
- No model accuracy/generalization claim is made. The local service remains
  unauthenticated, single-tenant, and not production-deployed.

## Commit/push decision

**GO for the initial commit and push:** explicit approval was received. Commit
`e8ef1c93adb7bb94b504de346e3f81e9242d56fe` was pushed to `origin/main`, and its
hosted CI run passed. This completes hosted CI verification for the `main` push
event. No GHCR release or image publication was performed.
