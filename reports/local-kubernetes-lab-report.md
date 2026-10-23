# Local Kubernetes Deployment Lab — Results

**Result:** Local Kind deployment and requested runtime exercises verified.
This is a single-node learning lab, not production Kubernetes or an accuracy
assessment. M4 (telemetry contract and generalization evidence) remains unchanged.

## Implementation

- Added `deploy/kubernetes/local/` resources for a restricted namespace,
  ConfigMap, no-token ServiceAccount, local PV/PVC, Deployment, ClusterIP Service,
  and Kustomize bundle.
- Added manifest policy validation and a negative security regression test.
- Added scripts to create the separate Kind cluster and exercise actual inference,
  invalid input, rollouts, failure injection, rollback, pod recreation, events,
  logs, and cgroup counters.
- Added the lab guide, design review, and ADR 0005 for the production artifact
  distribution and future GitOps boundary.
- Added PyYAML to the development dependencies for manifest validation.

## Executed evidence

| Check | Actual result |
|---|---|
| Existing application image | Reused `streaming-threat-api:milestone-2`; image ID `sha256:6e6d39efe3d513191785fce077e754fba60396669d22a16f4ecb554582aaefcb`, configured user `app`. No image rebuild, model retraining, GHCR publication, or model copy into the image occurred. |
| Kind cluster | Created only `network-threat-lab` with Kubernetes v1.35.0; node `network-threat-lab-control-plane` became Ready. Existing Kind clusters were not selected. The lab cluster remains running. |
| Deployment and Service | Deployment rolled out with 1/1 pod Running/Ready. ClusterIP Service `network-threat-api` was `10.96.11.132:8000`; EndpointSlice published the ready pod at `10.244.0.9:8000` after recovery. PVC bound to `network-threat-model-local` with `ROX` access. |
| Runtime security | Pod ran as UID 999, used the dedicated ServiceAccount with token automount disabled, could not write the mounted `model.pkl`, had a read-only root filesystem, dropped all capabilities, disabled privilege escalation, and used RuntimeDefault seccomp. |
| Real-model inference | Port-forwarded `POST /v1/predict` returned `prediction: 0`, `class_label: normal`, `model_score: 0.023613212630152702`, `threshold: 0.5`, model `m-e938dbe02eac44609ef11145e7eaa535`, schema `1.0.0`. This was a sanitized synthetic record and an actual response from the saved MLflow XGBoost pipeline. The score is uncalibrated and is not a calibrated threat-risk estimate. |
| Invalid schema | Same request with schema `99.0.0` returned HTTP 422, rejecting the unsupported version. |
| Successful rollout | `kubectl rollout restart` completed; revision changed from 4 to 5 and the deployment became available. |
| Failure and rollback | Setting image to `streaming-threat-api:unavailable-rollback-test` produced the expected `ErrImageNeverPull` event and stalled rollout. `kubectl rollout undo` restored `streaming-threat-api:local`; rollout completed. |
| Pod recreation | Deleted pod UID `23eed812-475e-467a-8aba-af150a6ac4c5`; the controller created ready replacement UID `e91edd7e-49bb-4ebc-8e5d-66eebcbe0a74`. Deployment condition `Available=True`; the Service EndpointSlice again had a ready endpoint. |
| Resource observation | Sample cgroup snapshot after the exercise: `memory.current=174940160` bytes (about 167 MiB); `cpu.stat` showed 3,942,324 microseconds cumulative CPU usage and 5 throttled periods at observation time. This is a snapshot, not a load benchmark or metrics-server result. |
| Events and logs | Captured Uvicorn readiness/liveness logs, ReplicaSet scaling events, expected image-pull failure events, and final Deployment conditions through the verification script. |
| Automated tests | `uv run --locked pytest -q`: 36 passed; one existing Starlette/httpx deprecation warning. This includes positive manifest-policy validation and rejection of a privileged-container mutation. |

The apply was accepted by the Kubernetes API, and both the manifest validator and
live deployment succeeded. The rollback command emitted a Kubernetes warning
about `kubectl.kubernetes.io/last-applied-configuration`; the restored manifest
still used the expected local image and the final rollout was available.

## Reproduction

From repository root, with Docker, Kind, kubectl, uv, the local image, and a
trusted model at `models/xgboost/`:

```bash
uv sync
uv run pytest -q
uv run ruff check src scripts tests
uv run python scripts/validate_k8s_manifests.py
./scripts/create_local_k8s_lab.sh
./scripts/verify_local_k8s_lab.sh
```

To remove only this learning cluster after collecting evidence:

```bash
kind delete cluster --name network-threat-lab
```

The helper uses `kubectl --context kind-network-threat-lab`; it does not change
the user's current context.

## Limitations and remaining risks

- The model is exposed by a host-backed local PV via Kind `extraMounts`. This is
  explicitly **not** a production distribution mechanism. Production requires an
  approved immutable artifact reference, integrity/provenance verification,
  authenticated access, auditability, and tested rollback.
- Single-node Kind does not verify multi-node scheduling, worker-node scaling,
  high availability, network policies, cloud storage, node failure, or workload
  disruption handling.
- No authentication, TLS/ingress, multi-tenancy, metrics server, alerting, GitOps,
  Terraform, cloud infrastructure, or production operations were implemented.
- No load, latency, throughput, accuracy, or generalization claim is made.
- Docker image vulnerability scanning was not repeated as part of this local lab;
  the existing CI scan evidence remains in the Milestone 3 report.

**Next recommended step:** keep the lab as a local learning environment and
preserve M4 as the next platform roadmap milestone. Before any shared or
production Kubernetes use, complete a separately reviewed model-artifact
distribution and identity/security design; do not promote this hostPath-backed
volume approach.
