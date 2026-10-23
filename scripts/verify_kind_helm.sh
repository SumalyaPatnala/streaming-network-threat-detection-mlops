#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="network-threat-lab"
CONTEXT="kind-${CLUSTER_NAME}"
NAMESPACE="threat-detection-lab"
RELEASE="m5-platform"
DEPLOYMENT="m5-platform-threat-detection"
SERVICE="m5-platform-threat-detection"
MODEL_ID="m-e938dbe02eac44609ef11145e7eaa535"
LOCAL_PORT="${LOCAL_PORT:-18081}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port_forward_log="$(mktemp "${TMPDIR:-/tmp}/m5-platform-port-forward.XXXXXX.log")"
port_forward_pid=""
trap 'if [[ -n "$port_forward_pid" ]]; then kill "$port_forward_pid" 2>/dev/null || true; wait "$port_forward_pid" 2>/dev/null || true; fi; rm -f "$port_forward_log"' EXIT

if [[ "$(kubectl config current-context)" != "$CONTEXT" ]]; then
    printf 'Active context changed; refusing the deployment smoke test.\n' >&2
    exit 1
fi
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
    "deployment/$DEPLOYMENT" --timeout=180s

pod="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pods \
    -l "app.kubernetes.io/instance=$RELEASE" \
    -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "$pod" ]]; then
    printf 'No pod belonging to Helm release %s was found.\n' "$RELEASE" >&2
    exit 1
fi

printf 'Helm release, probe configuration, image, and pod security:\n'
helm --kube-context "$CONTEXT" --namespace "$NAMESPACE" status "$RELEASE"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get deployment "$DEPLOYMENT" \
    -o jsonpath='image={.spec.template.spec.containers[0].image}{"\n"}startupProbe={.spec.template.spec.containers[0].startupProbe}{"\n"}readinessProbe={.spec.template.spec.containers[0].readinessProbe}{"\n"}livenessProbe={.spec.template.spec.containers[0].livenessProbe}{"\n"}runAsUser={.spec.template.spec.securityContext.runAsUser}rootFsReadOnly={.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}capabilities={.spec.template.spec.containers[0].securityContext.capabilities.drop}{"\n"}'
started="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod" \
    -o jsonpath='{.status.containerStatuses[0].started}')"
ready="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod" \
    -o jsonpath='{.status.containerStatuses[0].ready}')"
if [[ "$started" != "true" || "$ready" != "true" ]]; then
    printf 'Startup/readiness probes have not succeeded: started=%s ready=%s\n' \
        "$started" "$ready" >&2
    exit 1
fi
printf 'Kubernetes startup and readiness probes succeeded.\n'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "$pod" -- \
    python -c 'import os; from pathlib import Path; assert os.getuid()==999; assert not Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists(); p=Path("/models/xgboost/model.pkl"); assert p.is_file(); print(f"uid={os.getuid()} model={p} readable={os.access(p, os.R_OK)}")'
if kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "$pod" -- \
    python -c 'from pathlib import Path; Path("/models/xgboost/model.pkl").open("ab").close()' \
    >/dev/null 2>&1; then
    printf 'Model file unexpectedly allowed a write.\n' >&2
    exit 1
else
    printf 'Model artifact write attempt was denied as expected.\n'
fi

kubectl --context "$CONTEXT" --namespace "$NAMESPACE" port-forward \
    "service/$SERVICE" "$LOCAL_PORT:8000" >"$port_forward_log" 2>&1 &
port_forward_pid=$!
ready=0
for _ in $(seq 1 40); do
    if curl --silent --fail "http://127.0.0.1:$LOCAL_PORT/health/ready" >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [[ "$ready" != 1 ]]; then
    cat "$port_forward_log" >&2
    printf 'Helm API port-forward did not become ready.\n' >&2
    exit 1
fi

LOCAL_PORT="$LOCAL_PORT" MODEL_ID="$MODEL_ID" ROOT="$ROOT" \
    uv run --locked --no-sync python - <<'PY'
import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from prometheus_client.parser import text_string_to_metric_families

base = f"http://127.0.0.1:{os.environ['LOCAL_PORT']}"
model_id = os.environ["MODEL_ID"]
root = os.environ["ROOT"]
with open(f"{root}/data/samples/network-events.jsonl", encoding="utf-8") as stream:
    event = json.loads(next(stream))
record = {key: value for key, value in event.items() if key != "evidence_refs"}

def get(path):
    with urlopen(f"{base}{path}", timeout=10) as response:
        return response.status, response.headers, response.read()

for endpoint in ("/health/live", "/health/ready"):
    status, _, body = get(endpoint)
    assert status == 200, (endpoint, status, body)
    print(f"{endpoint}: HTTP {status} {body.decode()}")

def post(path, body):
    request = Request(
        f"{base}{path}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())

status, prediction = post("/v1/predict", record)
assert status == 200 and prediction["model_id"] == model_id, prediction
assert prediction["schema_version"] == "1.0.0"
print(f"real-model prediction: {json.dumps(prediction, sort_keys=True)}")

second = dict(record, event_id="kind-helm-batch-002")
status, batch = post("/v1/predict/batch", {"records": [record, second]})
assert status == 200 and len(batch["predictions"]) == 2, batch
assert batch["model_id"] == model_id
print(f"batch inference: HTTP {status}, predictions={len(batch['predictions'])}")

invalid = dict(record, schema_version="99.0.0")
status, rejected = post("/v1/predict", invalid)
assert status == 422, rejected
print(f"unsupported schema: HTTP {status}")

status, unconfigured = post("/v1/ingest", {"events": [event]})
assert status == 503, unconfigured
print("tenant ingestion with OIDC disabled: HTTP 503 (fail-closed as configured)")

status, _, payload = get("/metrics")
assert status == 200 and b"# HELP" in payload and b"# TYPE" in payload
families = list(text_string_to_metric_families(payload.decode()))
samples = [
    sample
    for family in families
    for sample in family.samples
]
model_samples = [
    sample for sample in samples
    if sample.name == "threat_detection_model_info"
    and sample.labels.get("model_id") == model_id
]
assert model_samples, "model identity metric is missing"
assert any(
    sample.name == "threat_detection_inference_requests_total"
    and sample.labels.get("model_id") == model_id
    for sample in samples
), "model-labeled inference counter is missing"
print(f"Prometheus exposition parsed successfully: {len(families)} metric families")
print("Helm deployment smoke passed; tenant routes remain closed without OIDC.")
PY
