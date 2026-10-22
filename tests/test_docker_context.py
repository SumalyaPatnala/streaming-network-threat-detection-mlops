from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts/validate_docker_context.py"


def test_repository_docker_context_policy_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(VALIDATOR)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Docker context policy passed" in result.stdout


def test_docker_context_policy_rejects_unreviewed_copy_sources(tmp_path: Path) -> None:
    script_directory = tmp_path / "scripts"
    script_directory.mkdir()
    copied_validator = script_directory / VALIDATOR.name
    shutil.copyfile(VALIDATOR, copied_validator)
    shutil.copyfile(ROOT / ".dockerignore", tmp_path / ".dockerignore")
    (tmp_path / "Dockerfile").write_text("COPY . /app\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(copied_validator)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "outside the reviewed allowlist" in result.stderr
