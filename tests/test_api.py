from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient

from threat_detection.api import (
    DEFAULT_SCHEMA_PATH,
    MAX_BATCH_SIZE,
    MAX_REQUEST_BYTES,
    SCHEMA_VERSION,
    ModelRuntime,
    PredictionService,
    create_app,
    load_model_runtime,
)

ROOT = Path(__file__).resolve().parents[1]
FEATURE_NAMES = tuple(
    json.loads(DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8"))["properties"][
        "features"
    ]["required"]
)
MODEL_ID = "m-test-approved-xgboost"


class XGBClassifier:
    classes_ = np.asarray([0, 1])


class FakePreprocessor:
    feature_names_in_ = np.asarray(FEATURE_NAMES, dtype=object)


class FakePipeline:
    def __init__(self, score: float = 0.73) -> None:
        self.score = score
        self.calls = 0
        self.named_steps = {
            "preprocessor": FakePreprocessor(),
            "classifier": XGBClassifier(),
        }

    def predict_proba(self, frame) -> np.ndarray:
        assert tuple(frame.columns) == FEATURE_NAMES
        self.calls += 1
        return np.asarray([[1.0 - self.score, self.score] for _ in range(len(frame))])


def fake_runtime(score: float = 0.73) -> ModelRuntime:
    return ModelRuntime(
        model=FakePipeline(score),
        feature_names=FEATURE_NAMES,
        model_id=MODEL_ID,
        schema_version=SCHEMA_VERSION,
    )


def sample_record(event_id: str = "safe-demo-001") -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "observed_at": "2026-10-22T12:00:00Z",
        "features": {
            name: None for name in FEATURE_NAMES
        }
        | {
            "dst_port": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 0.12,
            "src_bytes": 128,
            "dst_bytes": 512,
            "conn_state": "SF",
            "missed_bytes": 0,
            "src_pkts": 3,
            "src_ip_bytes": 260,
            "dst_pkts": 4,
            "dst_ip_bytes": 672,
            "ssl_version": "TLSv13",
        },
    }


def make_client(monkeypatch, score: float = 0.73, loader=None) -> TestClient:
    monkeypatch.setenv("MODEL_PATH", "/trusted/model/path")
    monkeypatch.setenv("MODEL_ID", MODEL_ID)
    if loader is None:
        loader = lambda *_args: fake_runtime(score)
    return TestClient(create_app(runtime_loader=loader))


def test_single_prediction_contract_and_model_metadata(monkeypatch) -> None:
    with make_client(monkeypatch) as client:
        response = client.post("/v1/predict", json=sample_record())

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["prediction"] == 1
    assert result["class_label"] == "attack"
    assert result["model_score"] == pytest.approx(0.73)
    assert result["threshold"] == 0.5
    assert result["model_id"] == MODEL_ID
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["event_id"] == "safe-demo-001"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda body: body.update(schema_version="2.0.0"), "schema_version"),
        (lambda body: body["features"].pop("dst_port"), "dst_port"),
        (lambda body: body["features"].update(extra_field="not allowed"), "extra_field"),
        (lambda body: body["features"].update(dst_port="443"), "dst_port"),
        (lambda body: body["features"].update(src_bytes=-1), "src_bytes"),
        (lambda body: body.update(unexpected=True), "unexpected"),
        (
            lambda body: body.update(observed_at="2026-10-22T12:00:00"),
            "observed_at",
        ),
    ],
)
def test_invalid_input_is_rejected_with_validation_details(
    monkeypatch, mutate, message
) -> None:
    body = sample_record()
    mutate(body)
    with make_client(monkeypatch) as client:
        response = client.post("/v1/predict", json=body)

    assert response.status_code == 422
    assert message in response.text


def test_batch_predictions_are_ordered_bounded_and_repeatable(monkeypatch) -> None:
    with make_client(monkeypatch) as client:
        body = {"records": [sample_record("first"), sample_record("second")]}
        first = client.post("/v1/predict/batch", json=body)
        second = client.post("/v1/predict/batch", json=body)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert [item["event_id"] for item in first.json()["predictions"]] == [
        "first",
        "second",
    ]
    assert len(first.json()["predictions"]) == 2


def test_batch_size_limit_is_enforced(monkeypatch) -> None:
    with make_client(monkeypatch) as client:
        response = client.post(
            "/v1/predict/batch",
            json={"records": [sample_record() for _ in range(MAX_BATCH_SIZE + 1)]},
        )

    assert response.status_code == 422
    assert "records" in response.text


def test_request_body_byte_limit_is_enforced(monkeypatch) -> None:
    with make_client(monkeypatch) as client:
        response = client.post(
            "/v1/predict",
            content=b'{"large":"' + b"x" * (MAX_REQUEST_BYTES + 1) + b'"}',
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 413
    assert "size limit" in response.json()["detail"]


def test_live_ready_and_model_info_endpoints(monkeypatch) -> None:
    with make_client(monkeypatch) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")
        info = client.get("/v1/model/info")

    assert live.status_code == 200
    assert live.json() == {"status": "alive"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}
    assert info.status_code == 200
    assert info.json() == {
        "model_id": MODEL_ID,
        "schema_version": SCHEMA_VERSION,
        "threshold": 0.5,
        "score_semantics": "uncalibrated positive-class model probability",
        "feature_count": 30,
    }


def test_readiness_is_false_before_startup() -> None:
    client = TestClient(create_app())
    live = client.get("/health/live")
    response = client.get("/health/ready")
    client.close()

    assert live.status_code == 200
    assert response.status_code == 503
    assert response.json()["detail"] == "Model is not ready"


def test_model_is_loaded_once_during_startup(monkeypatch) -> None:
    calls = 0

    def loader(*_args):
        nonlocal calls
        calls += 1
        return fake_runtime()

    with make_client(monkeypatch, loader=loader) as client:
        client.get("/health/ready")
        client.post("/v1/predict", json=sample_record())
        client.post("/v1/predict", json=sample_record())

    assert calls == 1


def test_startup_fails_explicitly_when_model_settings_are_missing(monkeypatch) -> None:
    monkeypatch.delenv("MODEL_PATH", raising=False)
    monkeypatch.delenv("MODEL_ID", raising=False)
    with pytest.raises(RuntimeError, match="MODEL_PATH"), TestClient(create_app()):
        pass


def test_startup_fails_explicitly_when_model_artifact_is_missing(monkeypatch) -> None:
    monkeypatch.setenv("MODEL_PATH", "/definitely/missing/model")
    monkeypatch.setenv("MODEL_ID", MODEL_ID)
    with pytest.raises(FileNotFoundError, match="missing or incomplete"), TestClient(
        create_app()
    ):
        pass


def test_startup_fails_explicitly_when_schema_is_missing(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("MODEL_PATH", "/trusted/model/path")
    monkeypatch.setenv("MODEL_ID", MODEL_ID)
    schema_path = tmp_path / "missing-schema.json"
    model_path = tmp_path / "existing-model"
    model_path.mkdir()
    (model_path / "MLmodel").write_text("test", encoding="utf-8")

    def loader(*_args):
        return load_model_runtime(model_path, MODEL_ID, schema_path)

    with pytest.raises(FileNotFoundError, match="schema is missing"), TestClient(
        create_app(runtime_loader=loader)
    ):
        pass


def test_model_loader_reports_mlflow_artifact_load_failure(tmp_path, monkeypatch) -> None:
    model_path = tmp_path / "model"
    model_path.mkdir()
    (model_path / "MLmodel").write_text("test", encoding="utf-8")

    def fail_loading(_path):
        raise OSError("corrupt model artifact")

    monkeypatch.setattr("threat_detection.api.mlflow.sklearn.load_model", fail_loading)
    with pytest.raises(RuntimeError, match="Unable to load selected MLflow model"):
        load_model_runtime(model_path, MODEL_ID)


def test_model_loader_rejects_schema_version_mismatch_before_loading(
    tmp_path, monkeypatch
) -> None:
    model_path = tmp_path / "model"
    model_path.mkdir()
    (model_path / "MLmodel").write_text("test", encoding="utf-8")
    schema_path = tmp_path / "schema.json"
    schema = json.loads(DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["properties"]["schema_version"]["const"] = "2.0.0"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    def should_not_load(_path):
        raise AssertionError("schema compatibility is checked before model loading")

    monkeypatch.setattr("threat_detection.api.mlflow.sklearn.load_model", should_not_load)
    with pytest.raises(ValueError, match="Incompatible input schema version"):
        load_model_runtime(model_path, MODEL_ID, schema_path)


def test_model_loader_rejects_fitted_feature_order_mismatch(tmp_path, monkeypatch) -> None:
    model_path = tmp_path / "model"
    model_path.mkdir()
    (model_path / "MLmodel").write_text("test", encoding="utf-8")
    model = FakePipeline()
    model.named_steps["preprocessor"].feature_names_in_ = np.asarray(
        list(reversed(FEATURE_NAMES)), dtype=object
    )
    monkeypatch.setattr(
        "threat_detection.api.mlflow.sklearn.load_model",
        lambda _path: model,
    )

    with pytest.raises(ValueError, match="feature names/order"):
        load_model_runtime(model_path, MODEL_ID)


def test_model_loader_loads_compatible_xgboost_pipeline(tmp_path, monkeypatch) -> None:
    model_path = tmp_path / "model"
    model_path.mkdir()
    (model_path / "MLmodel").write_text("test", encoding="utf-8")
    model = FakePipeline()
    monkeypatch.setattr(
        "threat_detection.api.mlflow.sklearn.load_model",
        lambda _path: model,
    )

    runtime = load_model_runtime(model_path, MODEL_ID)

    assert runtime.model is model
    assert runtime.feature_names == FEATURE_NAMES
    assert runtime.schema_version == SCHEMA_VERSION


def test_prediction_service_rejects_invalid_model_probability() -> None:
    runtime = fake_runtime()
    bad_model = FakePipeline(score=float("nan"))
    runtime = ModelRuntime(
        model=bad_model,
        feature_names=runtime.feature_names,
        model_id=runtime.model_id,
        schema_version=runtime.schema_version,
    )
    service = PredictionService(runtime)
    from threat_detection.api import PredictionRequest

    with pytest.raises(RuntimeError, match="invalid binary probability matrix"):
        service.predict(PredictionRequest.model_validate(sample_record()))
