#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform is required for fmt and validate." >&2
  exit 127
fi

terraform fmt -recursive -check "$ROOT/infra/terraform"
for environment in dev prod; do
  directory="$ROOT/infra/terraform/environments/$environment"
  terraform -chdir="$directory" init -backend=false -input=false
  terraform -chdir="$directory" validate
done
