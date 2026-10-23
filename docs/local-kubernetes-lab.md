# Local Kubernetes Deployment Lab

## Scope and status

This is a separately tracked, local infrastructure-learning lab. It does not
replace or reorder M4 (telemetry contract and generalization evidence), and it is
not a production deployment. The service remains unauthenticated and single-tenant.
The lab uses Kind because it runs a real Kubernetes control plane and worker-node
container locally without a cloud account or paid resources. One dedicated
single-node cluster is used to keep resource use bounded. The helper uses an
explicit Kind context and does not change the current kubectl context.

The namespace enforces Kubernetes Pod Security Standard `restricted`. The workload
uses a dedicated service account with API-token automount disabled; it needs no
Role, RoleBinding, or cluster-wide RBAC grant. The pod runs as UID/GID 999, drops
all capabilities, disallows privilege escalation, uses RuntimeDefault seccomp and
a read-only root filesystem, and has CPU/memory requests and limits. Startup,
readiness, and liveness probes, a bounded termination grace period, and a
zero-unavailable rolling update are configured.

## Model artifact boundary

Use only a trusted, existing MLflow XGBoost model artifact selected by the operator.
The model directory remains on the host and out of Git, the image, ConfigMaps, and
Kubernetes Secrets. Kind mounts that directory read-only into its dedicated node;
a local PersistentVolume/PVC presents it read-only to the API pod. The pod does
not use a direct `hostPath` volume. This local PV is still hostPath-backed at the
Kind node boundary and is **not an acceptable production model-distribution
strategy**.

The model ID in the ConfigMap is the specific Milestone 2 local artifact. If using
a different artifact, update the ID only after selecting and validating that
artifact and ensure it has the same v1 schema and feature contract. Never store
credentials or private model bytes in Kubernetes configuration resources.

## Prerequisites and startup

Requires Docker, Kind, kubectl, uv, and the repository's local uv environment.
The default helper expects:

- Image `streaming-threat-api:milestone-2`.
- Model at `models/xgboost/`, containing `MLmodel` and `model.pkl`.
- Available Docker resources for one Kubernetes node and one bounded API pod.

To select a different local model directory or already-built compatible image:

```bash
MODEL_DIR="$PWD/models/xgboost" \
SOURCE_IMAGE="streaming-threat-api:milestone-2" \
./scripts/create_local_k8s_lab.sh
```

The script validates the local model files, Docker image, manifest policy, and the
read-only node mount; creates only the `network-threat-lab` Kind cluster if absent;
loads the local image; applies the manifests; and waits for the PVC and Deployment.
If a cluster with that name already exists but lacks the expected model mount, the
script stops rather than modifying it. Other existing Kind clusters are not
selected or changed.

Useful read-only inspection commands:

```bash
kubectl --context kind-network-threat-lab get nodes -o wide
kubectl --context kind-network-threat-lab -n threat-detection-lab get \
  deployment,pods,services,endpoints,pvc
kubectl --context kind-network-threat-lab -n threat-detection-lab get events \
  --sort-by=.lastTimestamp
kubectl --context kind-network-threat-lab -n threat-detection-lab logs \
  deployment/network-threat-api
```

## Verification and failure recovery

Run the full local exercise after startup:

```bash
./scripts/verify_local_k8s_lab.sh
```

It verifies pod UID 999, read-only model access and no service-account token;
readiness and Service endpoints; and sends a sanitized synthetic v1 record through
the port-forward to the actual saved XGBoost model. It also verifies an unsupported
schema version is rejected (HTTP 422), performs a successful rollout restart,
injects an unavailable image to observe a stalled rollout, runs `kubectl rollout
undo`, checks the original image and readiness recover, deletes the pod to observe
controller recreation, and prints pod logs, events, deployment conditions, and
cgroup resource counters. The script does not claim a metrics-server measurement.
The test is an operational exercise, not an accuracy or production-load test.

Inspect the actual output and report before drawing conclusions. Automated tests
also run `scripts/validate_k8s_manifests.py`; they do not need Docker, Kind, model
files, or a cluster. The validator checks required resources, rollout/probe/
resource settings, Pod Security controls, service account boundaries, local model
mount, and rejects permissive container settings. This static policy validation
does not replace runtime verification.

Keep the cluster for further local practice, or remove only this named lab cluster
after collecting evidence:

```bash
kind delete cluster --name network-threat-lab
```

Do not remove the unrelated `basic-mlflow-cluster` or
`production-mlflow-setup` clusters.

## Security and operational limitations

- Kind and the local PV do not model cloud CSI, IAM, encrypted remote artifact
  stores, node isolation, multi-node scheduling, network policy, or production
  backup.
- The host model directory must be trusted, readable by UID 999 through its parent
  directories, and protected on the workstation. The node mount is read-only.
- The image uses `imagePullPolicy: Never`; the helper loads the local image into
  the Kind node. This is not a registry-promotion workflow.
- No authentication, tenant isolation, ingress, TLS, autoscaling, disruption
  budget, metrics server, alerting, or GitOps controller is included.
- Model and image provenance are not cryptographically verified by this lab.

## Future production artifact and GitOps decision

See [ADR 0005](adr/0005-local-kubernetes-model-and-gitops.md). Production
distribution should use an approved immutable model reference with integrity and
provenance verification, identity-based read access, auditability, and explicit
promotion/rollback. GitOps is a future deployment-control option that should pin
both image and model digests and enforce reviewed environment changes. Neither
production artifact distribution nor GitOps is implemented here.
