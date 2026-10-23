from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_DIR = ROOT / "deploy/kubernetes/local"
VALIDATOR = ROOT / "scripts/validate_k8s_manifests.py"


def _validate(manifest_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest-dir",
            str(manifest_dir),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_local_kubernetes_manifests_pass_security_validation() -> None:
    result = _validate(MANIFEST_DIR)

    assert result.returncode == 0, result.stderr
    assert "security policy passed" in result.stdout


def test_manifest_validator_rejects_privileged_container(tmp_path: Path) -> None:
    lab_dir = tmp_path / "local"
    shutil.copytree(MANIFEST_DIR, lab_dir)
    deployment_path = lab_dir / "deployment.yaml"
    deployment = yaml.safe_load(deployment_path.read_text(encoding="utf-8"))
    deployment["spec"]["template"]["spec"]["containers"][0]["securityContext"][
        "allowPrivilegeEscalation"
    ] = True
    deployment_path.write_text(yaml.safe_dump(deployment, sort_keys=False), encoding="utf-8")

    result = _validate(lab_dir)

    assert result.returncode == 1
    assert "disable privilege escalation" in result.stderr
