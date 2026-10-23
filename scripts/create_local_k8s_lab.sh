#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="network-threat-lab"
NAMESPACE="threat-detection-lab"
MODEL_DIR="${MODEL_DIR:-$ROOT/models/xgboost}"
SOURCE_IMAGE="${SOURCE_IMAGE:-streaming-threat-api:milestone-2}"
LOCAL_IMAGE="streaming-threat-api:local"
NODE_IMAGE="kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
NODE_NAME="${CLUSTER_NAME}-control-plane"
CONTEXT="kind-${CLUSTER_NAME}"

for command in docker kind kubectl python3 uv; do
    command -v "$command" >/dev/null || {
        printf 'Required command not found: %s\n' "$command" >&2
        exit 1
    }
done

MODEL_DIR="$(cd "$MODEL_DIR" && pwd -P)"
if [[ ! -f "$MODEL_DIR/MLmodel" || ! -f "$MODEL_DIR/model.pkl" ]]; then
    printf 'Expected trusted MLflow model files under %s\n' "$MODEL_DIR" >&2
    exit 1
fi
docker image inspect "$SOURCE_IMAGE" >/dev/null
docker tag "$SOURCE_IMAGE" "$LOCAL_IMAGE"
uv run --locked --no-sync python "$ROOT/scripts/validate_k8s_manifests.py"

if ! kind get clusters | grep -Fxq "$CLUSTER_NAME"; then
    config_file="$(mktemp "${TMPDIR:-/tmp}/network-threat-kind.XXXXXX.json")"
    trap 'rm -f "$config_file"' EXIT
    python3 - "$MODEL_DIR" "$NODE_IMAGE" "$config_file" <<'PY'
import json
import sys
from pathlib import Path

model_dir, node_image, output = sys.argv[1:]
config = {
    "apiVersion": "kind.x-k8s.io/v1alpha4",
    "kind": "Cluster",
    "nodes": [
        {
            "role": "control-plane",
            "image": node_image,
            "extraMounts": [
                {
                    "hostPath": model_dir,
                    "containerPath": "/mnt/host-model",
                    "readOnly": True,
                }
            ],
        }
    ],
}
Path(output).write_text(json.dumps(config), encoding="utf-8")
PY
    kind create cluster \
        --name "$CLUSTER_NAME" \
        --config "$config_file" \
        --wait 180s
    rm -f "$config_file"
    trap - EXIT
else
    if ! docker exec "$NODE_NAME" test -f /mnt/host-model/MLmodel; then
        printf 'Existing cluster %s does not have the required read-only model mount.\n' \
            "$CLUSTER_NAME" >&2
        exit 1
    fi
fi

if ! docker exec "$NODE_NAME" sh -c \
    'awk '\''$2 == "/mnt/host-model" && $4 ~ /(^|,)ro(,|$)/ { found=1 } END { exit !found }'\'' /proc/mounts'; then
    printf 'Model directory is not mounted read-only in the Kind node.\n' >&2
    exit 1
fi

kind load docker-image "$LOCAL_IMAGE" --name "$CLUSTER_NAME"
kubectl --context "$CONTEXT" apply -k "$ROOT/deploy/kubernetes/local"
kubectl --context "$CONTEXT" wait \
    --namespace "$NAMESPACE" \
    --for=jsonpath='{.status.phase}'=Bound \
    persistentvolumeclaim/network-threat-model \
    --timeout=90s
kubectl --context "$CONTEXT" rollout status \
    --namespace "$NAMESPACE" \
    deployment/network-threat-api \
    --timeout=240s

printf '\nLocal lab is ready. Current context was not changed.\n'
kubectl --context "$CONTEXT" get nodes -o wide
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pods,services,endpointslices,persistentvolumeclaims
