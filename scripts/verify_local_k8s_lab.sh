#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="network-threat-lab"
CONTEXT="kind-${CLUSTER_NAME}"
NAMESPACE="threat-detection-lab"
DEPLOYMENT="network-threat-api"
SERVICE="network-threat-api"
LOCAL_IMAGE="streaming-threat-api:local"
BAD_IMAGE="streaming-threat-api:unavailable-rollback-test"
LOCAL_PORT="${LOCAL_PORT:-18000}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
port_forward_log="$(mktemp "${TMPDIR:-/tmp}/network-threat-port-forward.XXXXXX.log")"
port_forward_pid=""
trap 'if [[ -n "$port_forward_pid" ]]; then kill "$port_forward_pid" 2>/dev/null || true; wait "$port_forward_pid" 2>/dev/null || true; fi; rm -f "$port_forward_log"' EXIT

kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
    "deployment/$DEPLOYMENT" --timeout=180s

pod_before="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pods \
    -l app.kubernetes.io/name=network-threat-api \
    -o jsonpath='{.items[0].metadata.name}')"
uid_before="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod_before" \
    -o jsonpath='{.metadata.uid}')"
revision_before="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get deployment "$DEPLOYMENT" \
    -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"

printf 'Initial pod=%s uid=%s revision=%s\n' "$pod_before" "$uid_before" "$revision_before"
printf '\nPod security and resources:\n'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod_before" \
    -o jsonpath='runAsUser={.spec.securityContext.runAsUser} serviceAccount={.spec.serviceAccountName} tokenAutomount={.spec.automountServiceAccountToken} modelReadOnly={.spec.containers[0].volumeMounts[0].readOnly} requests={.spec.containers[0].resources.requests} limits={.spec.containers[0].resources.limits}{"\n"}'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "$pod_before" -- \
    python -c 'import os; from pathlib import Path; assert os.getuid()==999; assert not os.access("/models/xgboost/model.pkl", os.W_OK); assert not Path("/var/run/secrets/kubernetes.io/serviceaccount/token").exists(); print("uid=999; model file not writable; service-account token absent")'

printf '\nStartup/readiness and endpoint:\n'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod_before" \
    -o jsonpath='ready={.status.containerStatuses[0].ready}{"\n"}'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get endpointslices \
    -l "kubernetes.io/service-name=$SERVICE" -o wide
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" logs "$pod_before" --tail=30

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
    printf 'Port-forwarded API readiness did not become healthy.\n' >&2
    exit 1
fi

printf '\nReal-model inference and invalid-schema rejection:\n'
python3 - "$LOCAL_PORT" <<'PY'
import json
import sys
from urllib.error import HTTPError
from urllib.request import Request, urlopen

port = int(sys.argv[1])
features = {
    "dst_port": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.12,
    "src_bytes": 128,
    "dst_bytes": 512,
    "conn_state": "SF",
    "missed_bytes": 0,
    "src_pkts": 3,
    "src_ip_bytes": 260,
    "dst_pkts": 4,
    "dst_ip_bytes": 672,
    "dns_qclass": None,
    "dns_qtype": None,
    "dns_rcode": None,
    "dns_AA": None,
    "dns_RD": None,
    "dns_RA": None,
    "dns_rejected": None,
    "ssl_version": "TLSv13",
    "ssl_cipher": "TLS_AES_128_GCM_SHA256",
    "ssl_resumed": "F",
    "ssl_established": "T",
    "http_trans_depth": None,
    "http_method": None,
    "http_version": None,
    "http_request_body_len": 0,
    "http_response_body_len": 0,
    "http_status_code": 0,
    "weird_notice": None,
}
record = {
    "schema_version": "1.0.0",
    "event_id": "kind-lab-synthetic-001",
    "observed_at": "2026-10-22T12:00:00Z",
    "features": features,
}
request = Request(
    f"http://127.0.0.1:{port}/v1/predict",
    data=json.dumps(record).encode(),
    headers={"Content-Type": "application/json"},
)
with urlopen(request, timeout=10) as response:
    result = json.load(response)
print(json.dumps(result, sort_keys=True))
assert result["model_id"] == "m-e938dbe02eac44609ef11145e7eaa535"
assert result["schema_version"] == "1.0.0"

invalid = dict(record, schema_version="99.0.0")
bad_request = Request(
    f"http://127.0.0.1:{port}/v1/predict",
    data=json.dumps(invalid).encode(),
    headers={"Content-Type": "application/json"},
)
try:
    urlopen(bad_request, timeout=10)
except HTTPError as error:
    body = error.read().decode()
    print(f"invalid schema HTTP {error.code}: {body}")
    assert error.code == 422
else:
    raise AssertionError("incompatible schema was not rejected")
PY

printf '\nSuccessful rolling update:\n'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout restart "deployment/$DEPLOYMENT"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
    "deployment/$DEPLOYMENT" --timeout=180s
revision_after="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get deployment "$DEPLOYMENT" \
    -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}')"
printf 'rollout revision %s -> %s\n' "$revision_before" "$revision_after"

printf '\nFailure injection and rollback:\n'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" set image \
    "deployment/$DEPLOYMENT" "api=$BAD_IMAGE"
if kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
    "deployment/$DEPLOYMENT" --timeout=45s; then
    printf 'Failure injection unexpectedly succeeded.\n' >&2
    exit 1
else
    printf 'Expected failed rollout observed for unavailable local image.\n'
fi
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pods -o wide
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get events --sort-by=.lastTimestamp | tail -15
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout undo "deployment/$DEPLOYMENT"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" rollout status \
    "deployment/$DEPLOYMENT" --timeout=180s
image_after_rollback="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get deployment "$DEPLOYMENT" \
    -o jsonpath='{.spec.template.spec.containers[0].image}')"
if [[ "$image_after_rollback" != "$LOCAL_IMAGE" ]]; then
    printf 'Rollback image mismatch: expected %s, got %s\n' "$LOCAL_IMAGE" "$image_after_rollback" >&2
    exit 1
fi
printf 'rollback restored %s\n' "$image_after_rollback"

printf '\nPod recreation:\n'
pod_to_delete="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pods \
    -l app.kubernetes.io/name=network-threat-api \
    -o jsonpath='{.items[0].metadata.name}')"
uid_to_delete="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod_to_delete" \
    -o jsonpath='{.metadata.uid}')"
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" delete pod "$pod_to_delete" --wait=true
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" wait \
    --for=condition=Ready pod \
    -l app.kubernetes.io/name=network-threat-api \
    --timeout=180s
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" wait \
    --for=condition=Available deployment/"$DEPLOYMENT" \
    --timeout=90s
pod_after="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pods \
    -l app.kubernetes.io/name=network-threat-api \
    -o jsonpath='{.items[0].metadata.name}')"
uid_after="$(kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get pod "$pod_after" \
    -o jsonpath='{.metadata.uid}')"
printf 'deleted pod=%s uid=%s; replacement pod=%s uid=%s\n' \
    "$pod_to_delete" "$uid_to_delete" "$pod_after" "$uid_after"
if [[ "$uid_to_delete" == "$uid_after" ]]; then
    printf 'Pod recreation did not produce a new UID.\n' >&2
    exit 1
fi

printf '\nRecovery readiness and resource use:\n'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" get endpointslices \
    -l "kubernetes.io/service-name=$SERVICE" -o wide
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" logs "$pod_after" --tail=30
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" exec "$pod_after" -- sh -c \
    'printf "memory.current="; cat /sys/fs/cgroup/memory.current; printf "cpu.stat="; tr "\n" " " < /sys/fs/cgroup/cpu.stat; printf "\n"'
kubectl --context "$CONTEXT" --namespace "$NAMESPACE" describe deployment "$DEPLOYMENT" | tail -45

printf '\nVerification complete. The local Kind cluster is left running.\n'
