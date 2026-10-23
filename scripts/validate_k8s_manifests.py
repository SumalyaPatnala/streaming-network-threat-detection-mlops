from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

DEFAULT_MANIFEST_DIR = (
    Path(__file__).resolve().parents[1] / "deploy" / "kubernetes" / "local"
)
EXPECTED_RESOURCES = {
    ("Namespace", "threat-detection-lab"),
    ("ConfigMap", "network-threat-api-config"),
    ("ServiceAccount", "network-threat-api"),
    ("PersistentVolume", "network-threat-model-local"),
    ("PersistentVolumeClaim", "network-threat-model"),
    ("Deployment", "network-threat-api"),
    ("Service", "network-threat-api"),
}
EXPECTED_LABEL = {"app.kubernetes.io/name": "network-threat-api"}


def _get(resources: dict[tuple[str, str], dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    return resources[(kind, name)]


def validate_manifest_directory(manifest_dir: Path) -> list[str]:
    errors: list[str] = []
    resources: dict[tuple[str, str], dict[str, Any]] = {}
    manifest_paths = sorted(
        path
        for path in manifest_dir.glob("*.yaml")
        if path.name != "kustomization.yaml"
    )
    if not manifest_paths:
        return [f"No Kubernetes resource manifests found in {manifest_dir}"]

    for path in manifest_paths:
        try:
            documents = yaml.safe_load_all(path.read_text(encoding="utf-8"))
            for document in documents:
                if not isinstance(document, dict):
                    errors.append(f"{path.name}: each YAML document must be an object")
                    continue
                kind = document.get("kind")
                name = document.get("metadata", {}).get("name")
                if not isinstance(kind, str) or not isinstance(name, str):
                    errors.append(f"{path.name}: kind and metadata.name are required")
                    continue
                key = (kind, name)
                if key in resources:
                    errors.append(f"{path.name}: duplicate resource {kind}/{name}")
                resources[key] = document
        except (OSError, yaml.YAMLError) as error:
            errors.append(f"{path.name}: unable to parse YAML: {error}")

    missing = EXPECTED_RESOURCES - resources.keys()
    unexpected = resources.keys() - EXPECTED_RESOURCES
    if missing:
        errors.append(f"Missing required resources: {sorted(missing)}")
    if unexpected:
        errors.append(f"Unexpected resources: {sorted(unexpected)}")
    if errors:
        return errors

    namespace = _get(resources, "Namespace", "threat-detection-lab")
    namespace_labels = namespace.get("metadata", {}).get("labels", {})
    if namespace_labels.get("pod-security.kubernetes.io/enforce") != "restricted":
        errors.append("Namespace must enforce the restricted Pod Security Standard")

    config = _get(resources, "ConfigMap", "network-threat-api-config")
    config_data = config.get("data", {})
    if config_data.get("MODEL_ID") != "m-e938dbe02eac44609ef11145e7eaa535":
        errors.append("ConfigMap must identify the explicitly selected local model")
    if config_data.get("MODEL_PATH") != "/models/xgboost":
        errors.append("ConfigMap MODEL_PATH must match the serving container contract")
    if any(key.lower().endswith(("password", "token", "secret", "credential")) for key in config_data):
        errors.append("ConfigMap must not contain secret-valued configuration")

    service_account = _get(resources, "ServiceAccount", "network-threat-api")
    if service_account.get("automountServiceAccountToken") is not False:
        errors.append("Application service account must disable token automount")

    pv = _get(resources, "PersistentVolume", "network-threat-model-local")
    pv_spec = pv.get("spec", {})
    if pv_spec.get("local", {}).get("path") != "/mnt/host-model":
        errors.append("Local model PV must use the documented kind node mount")
    if pv_spec.get("persistentVolumeReclaimPolicy") != "Retain":
        errors.append("Local model PV must retain the host data on claim deletion")

    pvc = _get(resources, "PersistentVolumeClaim", "network-threat-model")
    if pvc.get("spec", {}).get("storageClassName") != "":
        errors.append("Local model PVC must bind only to the explicitly declared local PV")

    deployment = _get(resources, "Deployment", "network-threat-api")
    deployment_spec = deployment.get("spec", {})
    pod_spec = deployment_spec.get("template", {}).get("spec", {})
    pod_labels = deployment_spec.get("template", {}).get("metadata", {}).get("labels", {})
    containers = pod_spec.get("containers", [])
    if len(containers) != 1:
        errors.append("Deployment must run exactly one inference container")
    if pod_spec.get("serviceAccountName") != "network-threat-api":
        errors.append("Deployment must use its dedicated service account")
    if pod_spec.get("automountServiceAccountToken") is not False:
        errors.append("Pod must disable Kubernetes API token automount")
    pod_security = pod_spec.get("securityContext", {})
    if (
        pod_security.get("runAsNonRoot") is not True
        or pod_security.get("runAsUser") == 0
        or pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
    ):
        errors.append("Pod security context must be non-root with RuntimeDefault seccomp")

    if containers:
        container = containers[0]
        container_security = container.get("securityContext", {})
        if container.get("imagePullPolicy") != "Never":
            errors.append("Local lab image must not be pulled from a registry")
        if container_security.get("allowPrivilegeEscalation") is not False:
            errors.append("Container must disable privilege escalation")
        if container_security.get("readOnlyRootFilesystem") is not True:
            errors.append("Container root filesystem must be read-only")
        if "ALL" not in container_security.get("capabilities", {}).get("drop", []):
            errors.append("Container must drop all Linux capabilities")
        for resource_name in ("requests", "limits"):
            values = container.get("resources", {}).get(resource_name, {})
            if not {"cpu", "memory"} <= values.keys():
                errors.append(f"Container resource {resource_name} must set CPU and memory")
        for probe_name, path in (
            ("startupProbe", "/health/ready"),
            ("readinessProbe", "/health/ready"),
            ("livenessProbe", "/health/live"),
        ):
            probe = container.get(probe_name, {})
            if probe.get("httpGet", {}).get("path") != path:
                errors.append(f"{probe_name} must check {path}")
        mounts = container.get("volumeMounts", [])
        model_mount = next((mount for mount in mounts if mount.get("name") == "model-artifact"), {})
        if model_mount.get("mountPath") != "/models/xgboost" or model_mount.get("readOnly") is not True:
            errors.append("Model artifact must be mounted at /models/xgboost read-only")
        if any(
            "secretKeyRef" in env.get("valueFrom", {})
            for env in container.get("env", [])
        ):
            errors.append("Deployment must not inject Kubernetes Secret references")

    volumes = pod_spec.get("volumes", [])
    model_volume = next((volume for volume in volumes if volume.get("name") == "model-artifact"), {})
    if model_volume.get("persistentVolumeClaim", {}).get("claimName") != "network-threat-model":
        errors.append("Model must be supplied through the local model PVC")
    if model_volume.get("persistentVolumeClaim", {}).get("readOnly") is not True:
        errors.append("Model PVC must be mounted read-only")
    if any("hostPath" in volume for volume in volumes):
        errors.append("Pod must not use direct hostPath; use the local PVC boundary")
    if pod_spec.get("hostNetwork") or pod_spec.get("hostPID") or pod_spec.get("hostIPC"):
        errors.append("Host namespaces are not allowed")
    if any(port.get("hostPort") for container in containers for port in container.get("ports", [])):
        errors.append("Host ports are not allowed")

    strategy = deployment_spec.get("strategy", {})
    rolling = strategy.get("rollingUpdate", {})
    if (
        strategy.get("type") != "RollingUpdate"
        or rolling.get("maxUnavailable") != 0
        or rolling.get("maxSurge") != 1
    ):
        errors.append("Deployment must preserve availability during rolling updates")
    if pod_spec.get("terminationGracePeriodSeconds", 0) < 30:
        errors.append("Pod must allow at least 30 seconds for graceful shutdown")

    service = _get(resources, "Service", "network-threat-api")
    service_spec = service.get("spec", {})
    if service_spec.get("type") != "ClusterIP":
        errors.append("Application Service must be ClusterIP")
    if service_spec.get("selector") != EXPECTED_LABEL or pod_labels.get(
        "app.kubernetes.io/name"
    ) != EXPECTED_LABEL["app.kubernetes.io/name"]:
        errors.append("Service selector must match Deployment pod labels")

    if any(kind in {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding", "Secret"} for kind, _ in resources):
        errors.append("No RBAC grants or Kubernetes Secrets are required for this local service")

    try:
        kustomization = yaml.safe_load(
            (manifest_dir / "kustomization.yaml").read_text(encoding="utf-8")
        )
        declared = set(kustomization.get("resources", []))
        actual = {path.name for path in manifest_paths}
        if declared != actual:
            errors.append(
                f"Kustomization resources do not match manifest files: "
                f"missing={sorted(actual - declared)}, extra={sorted(declared - actual)}"
            )
    except (OSError, yaml.YAMLError, AttributeError) as error:
        errors.append(f"Unable to validate kustomization.yaml: {error}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate local Kubernetes manifests and security policy.")
    parser.add_argument("--manifest-dir", type=Path, default=DEFAULT_MANIFEST_DIR)
    args = parser.parse_args()
    errors = validate_manifest_directory(args.manifest_dir)
    if errors:
        print("\n".join(f"ERROR: {error}" for error in errors), file=sys.stderr)
        return 1
    print("Kubernetes manifests and local security policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
