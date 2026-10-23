from __future__ import annotations

import json
import math
import os
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threat_detection.observability import DRIFT_FEATURE_ALERT, DRIFT_FEATURE_PSI

EPSILON = 1e-6
MAX_TENANTS = 2048


class DriftConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class FeatureReference:
    kind: str
    probabilities: tuple[float, ...]
    boundaries: tuple[float, ...] = ()
    categories: tuple[str, ...] = ()

    @classmethod
    def parse(cls, feature: str, value: Any) -> FeatureReference:
        if not isinstance(value, dict):
            raise DriftConfigurationError(f"Drift reference for {feature} must be an object")
        kind = value.get("kind")
        raw_probabilities = value.get("probabilities")
        if (
            kind not in {"numeric", "categorical"}
            or not isinstance(raw_probabilities, list)
            or not raw_probabilities
            or any(
                not isinstance(probability, (float, int))
                or isinstance(probability, bool)
                or not math.isfinite(probability)
                or probability < 0
                for probability in raw_probabilities
            )
            or not math.isclose(sum(raw_probabilities), 1.0, rel_tol=0, abs_tol=1e-6)
        ):
            raise DriftConfigurationError(
                f"Drift reference for {feature} has invalid probabilities or kind"
            )
        if kind == "numeric":
            raw_boundaries = value.get("boundaries")
            if (
                not isinstance(raw_boundaries, list)
                or any(
                    not isinstance(boundary, (float, int))
                    or isinstance(boundary, bool)
                    or not math.isfinite(boundary)
                    for boundary in raw_boundaries
                )
                or raw_boundaries != sorted(set(raw_boundaries))
                or len(raw_probabilities) != len(raw_boundaries) + 1
            ):
                raise DriftConfigurationError(
                    f"Numeric drift reference for {feature} has invalid boundaries"
                )
            return cls(
                kind=kind,
                probabilities=tuple(float(item) for item in raw_probabilities),
                boundaries=tuple(float(item) for item in raw_boundaries),
            )
        categories = value.get("categories")
        if (
            not isinstance(categories, list)
            or any(not isinstance(category, str) for category in categories)
            or len(categories) != len(set(categories))
            or len(raw_probabilities) != len(categories) + 1
        ):
            raise DriftConfigurationError(
                f"Categorical drift reference for {feature} has invalid categories"
            )
        return cls(
            kind=kind,
            probabilities=tuple(float(item) for item in raw_probabilities),
            categories=tuple(categories),
        )

    def bucket(self, value: Any) -> int | None:
        if value is None:
            return None
        if self.kind == "numeric":
            if (
                not isinstance(value, (float, int))
                or isinstance(value, bool)
                or not math.isfinite(value)
            ):
                return None
            return bisect_right(self.boundaries, float(value))
        if not isinstance(value, str):
            return None
        try:
            return self.categories.index(value)
        except ValueError:
            return len(self.categories)


@dataclass
class TenantWindow:
    counts: dict[str, list[int]]
    scores: dict[str, float] = field(default_factory=dict)
    alerts: dict[str, bool] = field(default_factory=dict)


class DriftMonitor:
    def __init__(
        self,
        references: dict[str, FeatureReference],
        threshold: float = 0.2,
        window_size: int = 100,
    ) -> None:
        if not 0 < threshold <= 10:
            raise DriftConfigurationError("Drift threshold must be within (0, 10]")
        if window_size < 2:
            raise DriftConfigurationError("Drift window size must be at least 2")
        self.references = references
        self.threshold = threshold
        self.window_size = window_size
        self._tenants: dict[str, TenantWindow] = {}

    @classmethod
    def from_file(
        cls,
        reference_path: Path,
        feature_names: tuple[str, ...],
        threshold: float = 0.2,
        window_size: int = 100,
    ) -> DriftMonitor:
        try:
            document = json.loads(reference_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise DriftConfigurationError(
                f"Unable to read drift reference: {reference_path}"
            ) from error
        raw_references = document.get("features") if isinstance(document, dict) else None
        if not isinstance(document, dict):
            raise DriftConfigurationError("Drift reference must be a JSON object")
        if document.get("schema_version") != "1.0.0":
            raise DriftConfigurationError("Unsupported drift reference schema version")
        if not isinstance(raw_references, dict) or not raw_references:
            raise DriftConfigurationError("Drift reference must define feature distributions")
        if not set(raw_references) <= set(feature_names):
            raise DriftConfigurationError("Drift reference includes unknown model features")
        references = {
            feature: FeatureReference.parse(feature, value)
            for feature, value in raw_references.items()
        }
        return cls(references, threshold=threshold, window_size=window_size)

    def observe(self, tenant_id: str, features: dict[str, Any]) -> dict[str, Any]:
        window = self._tenants.get(tenant_id)
        if window is None:
            if len(self._tenants) >= MAX_TENANTS:
                raise RuntimeError("Drift monitor tenant capacity reached")
            window = TenantWindow(
                counts={
                    name: [0] * len(reference.probabilities)
                    for name, reference in self.references.items()
                }
            )
            self._tenants[tenant_id] = window

        for feature, reference in self.references.items():
            bucket = reference.bucket(features.get(feature))
            if bucket is None:
                continue
            window.counts[feature][bucket] += 1
            sample_count = sum(window.counts[feature])
            if sample_count < self.window_size:
                continue
            actual = [count / sample_count for count in window.counts[feature]]
            score = sum(
                (observed - expected)
                * math.log((observed + EPSILON) / (expected + EPSILON))
                for observed, expected in zip(actual, reference.probabilities, strict=True)
            )
            alert = score >= self.threshold
            window.scores[feature] = score
            window.alerts[feature] = alert
            window.counts[feature] = [0] * len(reference.probabilities)
            tenant_scores = [
                tenant_window.scores[feature]
                for tenant_window in self._tenants.values()
                if feature in tenant_window.scores
            ]
            tenant_alerts = [
                tenant_window.alerts[feature]
                for tenant_window in self._tenants.values()
                if feature in tenant_window.alerts
            ]
            DRIFT_FEATURE_PSI.labels(feature=feature).set(max(tenant_scores))
            DRIFT_FEATURE_ALERT.labels(feature=feature).set(
                int(any(tenant_alerts))
            )

        return self.status(tenant_id)

    def status(self, tenant_id: str) -> dict[str, Any]:
        window = self._tenants.get(tenant_id)
        if window is None:
            return {
                "status": "collecting",
                "threshold": self.threshold,
                "window_size": self.window_size,
                "features": {},
            }
        return {
            "status": (
                "collecting"
                if not window.scores
                else "alert"
                if any(window.alerts.values())
                else "monitoring"
            ),
            "threshold": self.threshold,
            "window_size": self.window_size,
            "features": {
                feature: {
                    "population_stability_index": score,
                    "alert": window.alerts[feature],
                }
                for feature, score in window.scores.items()
            },
        }


def load_drift_monitor(
    feature_names: tuple[str, ...], threshold: float, window_size: int
) -> DriftMonitor | None:
    reference_path = os.environ.get("DRIFT_REFERENCE_PATH")
    if not reference_path:
        return None
    return DriftMonitor.from_file(
        Path(reference_path),
        feature_names,
        threshold=threshold,
        window_size=window_size,
    )
