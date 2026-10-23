#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MODEL_PATH="${MODEL_PATH:-$ROOT/models/xgboost}"
if [[ ! -f "$MODEL_PATH/MLmodel" ]]; then
    printf 'Local end-to-end demo requires the selected MLflow artifact at %s.\n' \
        "$MODEL_PATH" >&2
    printf 'Copy the trusted artifact to models/xgboost or set MODEL_PATH.\n' >&2
    exit 1
fi

MODEL_PATH="$MODEL_PATH" uv run --locked --no-sync pytest -q -s \
    tests/test_e2e_saved_model.py
