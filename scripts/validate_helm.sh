#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART="$ROOT/deploy/helm/threat-detection"
TEST_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"

helm lint "$CHART" --values "$CHART/values-dev.yaml"
helm lint "$CHART" --values "$CHART/values-prod.yaml" \
  --set "image.digest=$TEST_DIGEST"
helm template threat-demo "$CHART" --namespace threat-detection \
  --values "$CHART/values-dev.yaml" >/dev/null
helm template threat-prod "$CHART" --namespace threat-detection \
  --values "$CHART/values-prod.yaml" --set "image.digest=$TEST_DIGEST" >/dev/null

rendered_dev="$(helm template threat-demo "$CHART" --namespace threat-detection \
  --values "$CHART/values-dev.yaml")"
for expected in \
  "fsGroup: 999" \
  "automountServiceAccountToken: false" \
  "path: /health/ready" \
  "path: /health/live" \
  "readOnlyRootFilesystem: true" \
  "claimName: network-threat-model"; do
  if ! grep -Fq "$expected" <<<"$rendered_dev"; then
    echo "Rendered development chart is missing required setting: $expected" >&2
    exit 1
  fi
done

if helm template threat-invalid "$CHART" --set model.id=test >/dev/null 2>&1; then
  echo "Chart must reject a missing trusted model claim." >&2
  exit 1
fi
if helm template threat-invalid "$CHART" --values "$CHART/values-prod.yaml" \
  --set replicaCount=2 >/dev/null 2>&1; then
  echo "Chart must reject multiple replicas while using SQLite." >&2
  exit 1
fi
if helm template threat-invalid "$CHART" --values "$CHART/values-prod.yaml" \
  >/dev/null 2>&1; then
  echo "Chart must reject production configuration without an immutable image digest." >&2
  exit 1
fi
