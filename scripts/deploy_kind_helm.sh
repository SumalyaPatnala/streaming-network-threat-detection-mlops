#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="network-threat-lab"
CONTEXT="kind-${CLUSTER_NAME}"
NAMESPACE="threat-detection-lab"
RELEASE="m5-platform"
DEPLOYMENT="m5-platform-threat-detection"
IMAGE="streaming-threat-api:m5-local"
MODEL_ID="m-e938dbe02eac44609ef11145e7eaa535"
MODEL_CLAIM="network-threat-model"

for command in docker kind kubectl helm uv; do
    command -v "$command" >/dev/null || {
        printf 'Required command not found: %s\n' "$command" >&2
        exit 1
    }
done

if ! kind get clusters | grep -Fxq "$CLUSTER_NAME"; then
    printf 'Refusing to create or target a cluster: expected existing %s.\n' \
        "$CLUSTER_NAME" >&2
    exit 1
fi

namespace_owner="$(kubectl --context "$CONTEXT" get namespace "$NAMESPACE" \
    -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}')"
if [[ "$namespace_owner" != "streaming-network-threat-detection" ]]; then
    printf 'Refusing to deploy: namespace %s has unexpected ownership label %s.\n' \
        "$NAMESPACE" "$namespace_owner" >&2
    exit 1
fi

if [[ ! -f "$ROOT/models/xgboost/MLmodel" || ! -f "$ROOT/models/xgboost/model.pkl" ]]; then
    printf 'Expected the selected local MLflow model under %s/models/xgboost.\n' \
        "$ROOT" >&2
    exit 1
fi

claim_access="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" \
    get pvc "$MODEL_CLAIM" -o jsonpath='{.status.phase}:{.status.accessModes[0]}')"
if [[ "$claim_access" != "Bound:ReadOnlyMany" ]]; then
    printf 'Model PVC must be bound ReadOnlyMany; found %s.\n' \
        "$claim_access" >&2
    exit 1
fi

node_name="${CLUSTER_NAME}-control-plane"
if ! docker exec "$node_name" test -f /mnt/host-model/MLmodel \
    || ! docker exec "$node_name" sh -c \
        'awk '\''$2 == "/mnt/host-model" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }'\'' /proc/mounts'; then
    printf 'The selected model is not mounted read-only in the dedicated Kind node.\n' >&2
    exit 1
fi

uv run --locked --no-sync python "$ROOT/scripts/validate_k8s_manifests.py"
helm lint "$ROOT/deploy/helm/threat-detection" \
    --values "$ROOT/deploy/helm/threat-detection/values-dev.yaml"
docker build --tag "$IMAGE" "$ROOT"
kind load docker-image "$IMAGE" --name "$CLUSTER_NAME"

helm --kube-context "$CONTEXT" upgrade --install "$RELEASE" \
    "$ROOT/deploy/helm/threat-detection" \
    --namespace "$NAMESPACE" \
    --values "$ROOT/deploy/helm/threat-detection/values-dev.yaml" \
    --set image.repository=streaming-threat-api \
    --set image.tag=m5-local \
    --set image.pullPolicy=Never \
    --set model.id="$MODEL_ID" \
    --set model.existingClaim="$MODEL_CLAIM" \
    --wait \
    --timeout=5m

kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
    "deployment/$DEPLOYMENT" --timeout=180s
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get \
    deployment,pods,services \
    -l "app.kubernetes.io/instance=$RELEASE" -o wide

printf '\nHelm release deployed in the dedicated project Kind cluster.\n'
printf 'Existing network-threat-api Deployment was not modified.\n'
