# ADR 0005: Local Kubernetes Model Mount and Production Artifact Boundary

- **Status:** Accepted for the local learning lab; production distribution is proposed
- **Date:** 2026-10-22
- **Decision owner:** Project owner approval not recorded
- **Related review:** [Local Kubernetes lab design review](../design-reviews/local-kubernetes-lab.md)

## Context

The FastAPI container loads a fitted MLflow model from `MODEL_PATH` and validates
the model against the bundled, versioned v1 schema at startup. The local learning
goal requires real inference with an existing saved model while keeping model
bytes out of the image, repository, ConfigMap, and Kubernetes Secret. A local
Kind deployment is authorized; cloud provisioning and GHCR publication are not.

## Decision

For the local-only Kind lab, mount the operator-selected host model directory
read-only into the dedicated Kind node using a Kind `extraMount`. Expose that
directory to the pod through a node-affine local PersistentVolume and a
PersistentVolumeClaim. Set the pod volume and container volume mount read-only.
Run the service in a restricted namespace with a dedicated no-token ServiceAccount
and no RBAC grants.

This hostPath-backed arrangement is explicitly not suitable for production model
distribution. Production use requires a separately reviewed artifact-delivery
design. The proposed direction is an immutable model artifact reference with
cryptographic integrity/provenance verification, authenticated least-privilege
retrieval, audit records, version/schema compatibility checks, and deterministic
rollback. The delivery mechanism (for example, an approved artifact registry or
CSI-backed volume) remains undecided until trust, availability, retention, and
operational requirements are reviewed.

GitOps may later manage reviewed Kubernetes desired state, but must pin immutable
image and model references, validate policy, protect environment promotion, and
provide a tested rollback path. No GitOps controller or production cluster is
part of this ADR's implementation.

## Alternatives considered

- **Bake the model into the API image:** rejected because it couples model and
  application release cadence and would embed a private artifact in the image.
- **Store model bytes in Git, ConfigMap, or Secret:** rejected because those are
  not model-artifact distribution mechanisms and would expose large/private data
  through source or configuration storage.
- **Use the local host mount in production:** rejected because it is node-coupled,
  lacks portable integrity/provenance and lifecycle controls, and is not a
  resilient or auditable artifact supply chain.
- **Implement a production registry or CSI driver now:** deferred because no
  production cluster, provider, identity system, or paid-service approval exists.
- **Add GitOps now:** deferred until an approved target cluster and image/model
  promotion and authorization policies exist.

## Consequences and follow-up

- The local lab can exercise actual model loading and Kubernetes rollout behavior
  without model retraining, registry publication, or cloud resources.
- The host model directory and Kind node are trusted local development components;
  this design does not provide production isolation or provenance.
- Record runtime inference, rollout, failure-injection, rollback, and recovery
  evidence in the separate local-lab report.
- Before production deployment, complete a design review covering artifact
  registry/CSI choice, digest and signature verification, access identity,
  revocation, retention, availability, backup, promotion, and GitOps boundaries.
