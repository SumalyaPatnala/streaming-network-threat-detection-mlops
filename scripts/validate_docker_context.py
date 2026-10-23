from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DOCKERIGNORE_PATTERNS = {
    ".env",
    ".env.*",
    ".aws/",
    ".ssh/",
    "*.crt",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.pem",
    "*.secret",
    "*.token",
    "*credential*",
    "credentials*",
    "data/",
    "mlartifacts/",
    "mlflow.db*",
    "mlruns/",
    "models/",
    "secrets/",
    "*.sqlite",
    "*.sqlite3",
}
ALLOWED_COPY_SOURCES = {
    "pyproject.toml",
    "uv.lock",
    "src/threat_detection",
    "schemas/network-flow-model-input-v1.schema.json",
    "schemas/network-security-event-v1.schema.json",
    "schemas/feature-drift-reference-v1.schema.json",
}


def validate_context_policy(
    dockerignore_path: Path = ROOT / ".dockerignore",
    dockerfile_path: Path = ROOT / "Dockerfile",
) -> list[str]:
    errors: list[str] = []
    patterns = {
        line.strip()
        for line in dockerignore_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing = REQUIRED_DOCKERIGNORE_PATTERNS - patterns
    if missing:
        errors.append(f".dockerignore is missing required patterns: {sorted(missing)}")

    for line_number, line in enumerate(
        dockerfile_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        fields = line.split()
        if not fields or fields[0].upper() not in {"COPY", "ADD"}:
            continue
        if fields[0].upper() == "ADD":
            errors.append(f"Dockerfile:{line_number}: ADD is not allowed")
            continue
        sources = [field for field in fields[1:] if not field.startswith("--")]
        if len(sources) < 2:
            errors.append(f"Dockerfile:{line_number}: COPY must use explicit sources")
            continue
        if any(source not in ALLOWED_COPY_SOURCES for source in sources[:-1]):
            errors.append(
                f"Dockerfile:{line_number}: COPY source is outside the reviewed allowlist"
            )

    return errors


def main() -> int:
    errors = validate_context_policy()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Docker context policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
