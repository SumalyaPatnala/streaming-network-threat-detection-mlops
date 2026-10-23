# Design Review: Local Kubernetes Deployment Lab

- **Status:** Local design and runtime review completed; production review remains out of scope
- **Scope:** Isolated Kind learning environment for the existing API and saved model
- **Out of scope:** Production Kubernetes, GitOps, Terraform, cloud resources, Kafka,
  telemetry normalization, tenant isolation, and model retraining

## Review summary

Use one dedicated Kind cluster with a pinned, locally available Kubernetes node
image. A separate context avoids changing the operator's current context or
touching other clusters. The image is reused and loaded into Kind; there is no
GHCR pull or publication.

Model bytes remain outside Git and the image. A read-only Kind node mount plus
node-affine local PV/PVC provides the artifact to a restricted pod. This is a
local-only exception; production distribution is unresolved and covered by
[ADR 0005](../adr/0005-local-kubernetes-model-and-gitops.md).

The workload has a ClusterIP Service, bounded CPU/memory, startup/readiness/
liveness checks, rolling update configuration, a 30-second graceful shutdown,
UID/GID 999, read-only root filesystem, no privilege escalation, no capabilities,
RuntimeDefault seccomp, and no API token/RBAC. Static validation is executable
through pytest. Runtime review requires evidence from the deployment report and
must not be inferred from valid YAML.

## Trade-offs and risks

- A single node minimizes local resource use but cannot demonstrate worker-node
  scheduling, high availability, autoscaling, disruption budgets, or network policy.
- A local PV is simple and private but tied to a single Kind node and host path.
- No auth, TLS, ingress, tenant boundaries, metrics-server, alerting, or production
  secrets handling is modeled.
- Model trust is operator responsibility; this lab does not verify signatures or
  prove provenance.
- Failure injection must use the unavailable image only in the isolated lab and
  must verify rollout undo restores the working local image.

## Required review evidence

1. Restricted namespace and automated manifest security validation.
2. Running pod UID, readiness, endpoint, and real saved-model response.
3. Invalid schema rejection.
4. Successful restart rollout, failed rollout observation, rollback, and pod
   recreation.
5. Captured events, logs, resource counters, and observed recovery behavior.

The [deployment report](../../reports/local-kubernetes-lab-report.md) records
actual runtime output for the required local evidence. Production artifact
distribution and GitOps remain open design items.
