from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from threat_detection.api import NetworkFlowFeatures
from threat_detection.training import LEAKAGE_PRONE_COLUMNS, prepare_features

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/network-flow-model-input-v1.schema.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_v1_schema_matches_train_time_feature_names() -> None:
    schema = _schema()
    feature_schema = schema["properties"]["features"]
    feature_names = feature_schema["required"]
    properties = feature_schema["properties"]

    assert schema["properties"]["schema_version"]["const"] == "1.0.0"
    assert len(feature_names) == 30
    assert len(feature_names) == len(set(feature_names))
    assert set(feature_names) == set(properties)
    assert feature_schema["additionalProperties"] is False

    frame = pd.DataFrame({name: [None] for name in feature_names})
    frame["label"] = [1]
    frame["type"] = ["attack"]
    assert list(prepare_features(frame).columns) == feature_names
    assert list(NetworkFlowFeatures.model_fields) == feature_names


def test_v1_schema_rejects_leakage_and_identity_fields() -> None:
    feature_names = set(_schema()["properties"]["features"]["required"])

    assert feature_names.isdisjoint(LEAKAGE_PRONE_COLUMNS)
    assert "label" not in feature_names
    assert "type" not in feature_names
    assert "event_id" not in feature_names
    assert "observed_at" not in feature_names


def test_schema_marks_model_features_nullable_for_missing_telemetry() -> None:
    feature_properties = _schema()["properties"]["features"]["properties"]

    assert all("null" in property_schema["type"] for property_schema in feature_properties.values())
