from __future__ import annotations

import json
from pathlib import Path

import pytest

from threat_detection.drift import DriftConfigurationError, DriftMonitor


def test_drift_windows_are_scoped_per_tenant_and_alert_on_shift(tmp_path) -> None:
    monitor = DriftMonitor.from_file(
        reference_path_for(
            tmp_path,
            {
                "schema_version": "1.0.0",
                "features": {
                    "duration": {
                        "kind": "numeric",
                        "boundaries": [1.0, 2.0],
                        "probabilities": [0.0, 1.0, 0.0],
                    },
                    "proto": {
                        "kind": "categorical",
                        "categories": ["tcp", "udp"],
                        "probabilities": [1.0, 0.0, 0.0],
                    },
                },
            }
        ),
        feature_names=("duration", "proto"),
        threshold=0.2,
        window_size=4,
    )

    for _ in range(4):
        monitor.observe("tenant-a", {"duration": 1.5, "proto": "tcp"})
        result = monitor.observe("tenant-b", {"duration": 9.0, "proto": "other"})

    assert monitor.status("tenant-a")["status"] == "monitoring"
    assert monitor.status("tenant-a")["features"]["duration"]["alert"] is False
    assert result["status"] == "alert"
    assert result["features"]["duration"]["alert"] is True
    assert result["features"]["proto"]["alert"] is True
    assert monitor.status("tenant-c")["status"] == "collecting"


def test_null_features_do_not_count_toward_a_drift_window() -> None:
    monitor = DriftMonitor(
        references_from_data(
            {
                "duration": {
                    "kind": "numeric",
                    "boundaries": [1],
                    "probabilities": [0.5, 0.5],
                }
            }
        ),
        threshold=0.2,
        window_size=2,
    )

    first = monitor.observe("tenant-a", {"duration": None})
    assert first["status"] == "collecting"
    assert first["features"] == {}
    second = monitor.observe("tenant-a", {"duration": 2})
    assert second["status"] == "collecting"
    third = monitor.observe("tenant-a", {"duration": 2})
    assert third["status"] == "alert"


@pytest.mark.parametrize(
    "reference",
    [
        {"schema_version": "2.0.0", "features": {"duration": {}}},
        {
            "schema_version": "1.0.0",
            "features": {
                "unknown": {
                    "kind": "numeric",
                    "boundaries": [],
                    "probabilities": [1],
                }
            },
        },
        {
            "schema_version": "1.0.0",
            "features": {
                "duration": {
                    "kind": "numeric",
                    "boundaries": [1],
                    "probabilities": [0.5, 0.2],
                }
            },
        },
    ],
)
def test_rejects_incompatible_drift_reference(tmp_path, reference) -> None:
    reference_path = tmp_path / "reference.json"
    reference_path.write_text(json.dumps(reference), encoding="utf-8")

    with pytest.raises(DriftConfigurationError):
        DriftMonitor.from_file(reference_path, feature_names=("duration",))


def reference_path_for(tmp_path: Path, reference: dict) -> Path:
    path = tmp_path / "reference.json"
    path.write_text(json.dumps(reference), encoding="utf-8")
    return path


def references_from_data(data: dict):
    from threat_detection.drift import FeatureReference

    return {
        feature: FeatureReference.parse(feature, reference)
        for feature, reference in data.items()
    }
