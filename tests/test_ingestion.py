from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.testclient import TestClient

from threat_detection.api import (
    DEFAULT_SCHEMA_PATH,
    SCHEMA_VERSION,
    IngestEvent,
    ModelRuntime,
    TenantRateLimiter,
    create_app,
)
from threat_detection.identity import (
    IdentityProviderUnavailableError,
    OIDCVerifier,
    TenantPrincipal,
)
from threat_detection.splunk import SplunkDeliveryError, SplunkHECSink

ROOT = Path(__file__).resolve().parents[1]
FEATURE_NAMES = tuple(
    json.loads(DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8"))["properties"][
        "features"
    ]["required"]
)


def test_versioned_sample_events_validate_against_ingestion_contract() -> None:
    fixture = ROOT / "data" / "samples" / "network-events.jsonl"
    schema = json.loads(
        (ROOT / "schemas" / "network-security-event-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    events = [
        IngestEvent.model_validate(json.loads(line))
        for line in fixture.read_text(encoding="utf-8").splitlines()
    ]

    assert len(events) == 2
    assert all(event.schema_version == "1.0.0" for event in events)
    assert schema["properties"]["features"]["$ref"] == (
        "network-flow-model-input-v1.schema.json#/properties/features"
    )
    assert set(schema["required"]) == {
        "schema_version",
        "event_id",
        "observed_at",
        "features",
        "evidence_refs",
    }


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
        return np.asarray([[1 - self.score, self.score] for _ in range(len(frame))])


class FakeVerifier:
    def verify(self, token: str) -> TenantPrincipal:
        if token == "tenant-a":
            return TenantPrincipal(
                tenant_id="tenant-a",
                subject="analyst-a",
                roles=frozenset({"events:write", "analyst"}),
            )
        if token == "tenant-b":
            return TenantPrincipal(
                tenant_id="tenant-b",
                subject="analyst-b",
                roles=frozenset({"events:write", "analyst"}),
            )
        if token == "writer-a":
            return TenantPrincipal(
                tenant_id="tenant-a",
                subject="writer-a",
                roles=frozenset({"events:write"}),
            )
        raise ValueError("Invalid bearer token")


class StaticSigningKey:
    def __init__(self, key) -> None:
        self.key = key


class StaticJwks:
    def __init__(self, key) -> None:
        self.signing_key = StaticSigningKey(key)

    def get_signing_key_from_jwt(self, _token: str) -> StaticSigningKey:
        return self.signing_key


class RecordingSink:
    def __init__(
        self, fail_once: bool = False, triage_fail_once: bool = False
    ) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.triage_calls: list[tuple[str, dict]] = []
        self.fail_once = fail_once
        self.triage_fail_once = triage_fail_once

    def send(
        self, tenant_id: str, record: dict, correlation_id: str | None = None
    ) -> None:
        record = {**record, "correlation_id": correlation_id}
        self.calls.append((tenant_id, record))
        if self.fail_once:
            self.fail_once = False
            raise SplunkDeliveryError("test delivery failure")

    def send_triage(
        self, tenant_id: str, record: dict, correlation_id: str | None = None
    ) -> None:
        record = {**record, "correlation_id": correlation_id}
        self.triage_calls.append((tenant_id, record))
        if self.triage_fail_once:
            self.triage_fail_once = False
            raise SplunkDeliveryError("test triage delivery failure")


def sample_event(event_id: str = "replay-001") -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "observed_at": "2026-10-22T12:00:00Z",
        "features": {name: None for name in FEATURE_NAMES},
        "evidence_refs": [f"zeek://conn.log#{event_id}"],
    }


@contextmanager
def tenant_client(monkeypatch) -> Iterator[TestClient]:
    monkeypatch.setenv("MODEL_PATH", "/trusted/model/path")
    monkeypatch.setenv("MODEL_ID", "m-test-approved-xgboost")
    for name in (
        "OIDC_ISSUER",
        "OIDC_AUDIENCE",
        "OIDC_JWKS_URL",
        "SPLUNK_HEC_URL",
        "SPLUNK_HEC_TOKEN",
        "SPLUNK_INDEX",
        "EVENT_STORE_PATH",
        "DRIFT_REFERENCE_PATH",
        "DRIFT_PSI_THRESHOLD",
        "DRIFT_WINDOW_SIZE",
    ):
        monkeypatch.delenv(name, raising=False)
    runtime = ModelRuntime(
        model=FakePipeline(),
        feature_names=FEATURE_NAMES,
        model_id="m-test-approved-xgboost",
        schema_version=SCHEMA_VERSION,
    )
    with TestClient(
        create_app(runtime_loader=lambda *_args: runtime)
    ) as client:
        client.app.state.identity_verifier = FakeVerifier()
        yield client


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_ingest_is_idempotent_and_returns_traceable_uncalibrated_prediction(
    monkeypatch,
) -> None:
    with tenant_client(monkeypatch) as client:
        body = {"events": [sample_event()]}
        first = client.post("/v1/ingest", json=body, headers=bearer("tenant-a"))
        second = client.post("/v1/ingest", json=body, headers=bearer("tenant-a"))
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        result = first.json()[0]
        assert result["event_id"] == "replay-001"
        assert result["prediction"]["model_id"] == "m-test-approved-xgboost"
        assert result["prediction"]["predicted_at"]
        assert result["prediction"]["evidence_refs"] == [
            "zeek://conn.log#replay-001"
        ]
        assert result["prediction"]["model_score"] == pytest.approx(0.73)
        assert result["response_recommendation"] == "analyst_review"
        assert result["duplicate"] is False
        assert second.json()[0]["duplicate"] is True
        assert client.app.state.prediction_service.runtime.model.calls == 1


def test_conflicting_duplicate_and_caller_selected_tenant_are_rejected(
    monkeypatch,
) -> None:
    with tenant_client(monkeypatch) as client:
        first = sample_event()
        accepted = client.post(
            "/v1/ingest", json={"events": [first]}, headers=bearer("tenant-a")
        )
        changed = sample_event()
        changed["features"]["proto"] = "udp"
        conflict = client.post(
            "/v1/ingest", json={"events": [changed]}, headers=bearer("tenant-a")
        )
        forged = sample_event("forged-001")
        forged["tenant_id"] = "tenant-b"
        rejected = client.post(
            "/v1/ingest", json={"events": [forged]}, headers=bearer("tenant-a")
        )

    assert accepted.status_code == 200
    assert conflict.status_code == 409
    assert rejected.status_code == 422


def test_signed_oidc_token_authenticates_ingestion_end_to_end(monkeypatch) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = OIDCVerifier(
        issuer="https://issuer.example.test/",
        audience="network-api",
        jwks_uri="https://issuer.example.test/jwks",
    )
    verifier._jwks = StaticJwks(private_key.public_key())
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iss": "https://issuer.example.test/",
            "aud": "network-api",
            "sub": "tenant-a-analyst",
            "tenant_id": "tenant-a",
            "roles": ["events:write"],
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
    )

    with tenant_client(monkeypatch) as client:
        client.app.state.identity_verifier = verifier
        response = client.post(
            "/v1/ingest",
            json={"events": [sample_event()]},
            headers=bearer(token),
        )

    assert response.status_code == 200, response.text
    assert response.json()[0]["event_id"] == "replay-001"


def test_event_and_incident_access_are_tenant_scoped_and_triage_is_human(
    monkeypatch,
) -> None:
    with tenant_client(monkeypatch) as client:
        ingested = client.post(
            "/v1/ingest",
            json={"events": [sample_event()]},
            headers=bearer("tenant-a"),
        )
        hidden = client.get(
            "/v1/events/replay-001", headers=bearer("tenant-b")
        )
        other_tenant_incidents = client.get(
            "/v1/incidents", headers=bearer("tenant-b")
        )
        writer_cannot_triage = client.post(
            "/v1/incidents/replay-001/triage",
            json={"decision": "acknowledged"},
            headers=bearer("writer-a"),
        )
        sink = RecordingSink()
        client.app.state.splunk_sink = sink
        triaged = client.post(
            "/v1/incidents/replay-001/triage",
            json={"decision": "acknowledged"},
            headers={**bearer("tenant-a"), "X-Request-ID": "triage-request-001"},
        )
        visible = client.get(
            "/v1/incidents", headers=bearer("tenant-a")
        )

    assert ingested.status_code == 200
    assert hidden.status_code == 404
    assert other_tenant_incidents.status_code == 200
    assert other_tenant_incidents.json() == []
    assert writer_cannot_triage.status_code == 403
    assert triaged.status_code == 200
    assert triaged.json()["reviewed_by"] == "analyst-a"
    assert sink.triage_calls[0][0] == "tenant-a"
    assert sink.triage_calls[0][1]["evidence_refs"] == [
        "zeek://conn.log#replay-001"
    ]
    assert sink.triage_calls[0][1]["correlation_id"] == "triage-request-001"
    assert visible.status_code == 200
    assert visible.json()[0]["triage_status"] == "acknowledged"
    assert visible.json()[0]["triage_history"] == [
        {
            "decision": "acknowledged",
            "reviewed_by": "analyst-a",
            "recorded_at": triaged.json()["recorded_at"],
        }
    ]


def test_triage_is_persisted_when_splunk_delivery_fails(monkeypatch) -> None:
    with tenant_client(monkeypatch) as client:
        ingested = client.post(
            "/v1/ingest",
            json={"events": [sample_event()]},
            headers=bearer("tenant-a"),
        )
        client.app.state.splunk_sink = RecordingSink(triage_fail_once=True)
        failed_delivery = client.post(
            "/v1/incidents/replay-001/triage",
            json={"decision": "dismissed"},
            headers=bearer("tenant-a"),
        )
        stored = client.get(
            "/v1/events/replay-001", headers=bearer("tenant-a")
        )

    assert ingested.status_code == 200
    assert failed_delivery.status_code == 503
    assert stored.status_code == 200
    assert stored.json()["triage_status"] == "dismissed"
    assert stored.json()["triage_history"][0]["decision"] == "dismissed"


def test_ingestion_requires_verified_tenant_identity_and_rate_limits(
    monkeypatch,
) -> None:
    with tenant_client(monkeypatch) as client:
        client.app.state.identity_verifier = None
        unconfigured = client.post(
            "/v1/ingest", json={"events": [sample_event()]}
        )
        client.app.state.identity_verifier = FakeVerifier()
        client.app.state.tenant_rate_limiter = TenantRateLimiter(limit=1)
        first = client.post(
            "/v1/ingest",
            json={"events": [sample_event("first")]},
            headers=bearer("tenant-a"),
        )
        limited = client.post(
            "/v1/ingest",
            json={"events": [sample_event("second")]},
            headers=bearer("tenant-a"),
        )

    assert unconfigured.status_code == 503
    assert first.status_code == 200
    assert limited.status_code == 429


def test_identity_provider_outage_fails_closed_with_service_unavailable(
    monkeypatch,
) -> None:
    class UnavailableVerifier:
        def verify(self, _token: str) -> TenantPrincipal:
            raise IdentityProviderUnavailableError("signing keys unavailable")

    with tenant_client(monkeypatch) as client:
        client.app.state.identity_verifier = UnavailableVerifier()
        response = client.post(
            "/v1/ingest",
            json={"events": [sample_event()]},
            headers=bearer("unavailable"),
        )

    assert response.status_code == 503
    assert "signing keys" in response.json()["detail"]


def test_drift_status_is_explicitly_unconfigured_without_reference(
    monkeypatch,
) -> None:
    with tenant_client(monkeypatch) as client:
        response = client.get("/v1/monitoring/drift", headers=bearer("tenant-a"))

    assert response.status_code == 200
    assert response.json()["status"] == "not_configured"


def test_splunk_failure_is_retryable_without_reinference(monkeypatch) -> None:
    with tenant_client(monkeypatch) as client:
        sink = RecordingSink(fail_once=True)
        client.app.state.splunk_sink = sink
        body = {"events": [sample_event()]}
        failed = client.post(
            "/v1/ingest",
            json=body,
            headers={**bearer("tenant-a"), "X-Request-ID": "ingest-request-001"},
        )
        retried = client.post("/v1/ingest", json=body, headers=bearer("tenant-a"))
        assert failed.status_code == 503
        assert retried.status_code == 200
        assert retried.json()[0]["duplicate"] is True
        assert len(sink.calls) == 2
        assert sink.calls[0][1]["correlation_id"] == "ingest-request-001"
        assert client.app.state.prediction_service.runtime.model.calls == 1


def test_splunk_payload_omits_raw_features_and_preserves_evidence(
    monkeypatch,
) -> None:
    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b'{"text":"Success","code":0}'

    captured: dict[str, object] = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("threat_detection.splunk.urlopen", fake_urlopen)
    event = {
        "event_id": "replay-001",
        "evidence_refs": ["zeek://conn.log#replay-001"],
        "prediction": {
            "observed_at": "2026-10-22T12:00:00Z",
            "predicted_at": "2026-10-22T12:00:01Z",
            "model_id": "m-test",
            "schema_version": SCHEMA_VERSION,
            "prediction": 1,
            "class_label": "attack",
            "model_score": 0.73,
            "threshold": 0.5,
        },
    }
    SplunkHECSink(
        "https://splunk.example.test:8088/services/collector/event",
        "test-token",
        "security",
    ).send("tenant-a", event, "request-001")

    request = captured["request"]
    assert request.get_header("Authorization") == "Splunk test-token"
    payload = json.loads(request.data)
    assert payload["index"] == "security"
    assert payload["event"]["tenant_id"] == "tenant-a"
    assert payload["event"]["model_version"] == "m-test"
    assert payload["event"]["correlation_id"] == "request-001"
    assert payload["event"]["evidence_refs"] == ["zeek://conn.log#replay-001"]
    assert payload["event"]["score_semantics"].startswith("uncalibrated")
    assert payload["event"]["response_recommendation"] == "analyst_review"
    assert "features" not in payload["event"]
    assert captured["timeout"] == 5
    sink = SplunkHECSink(
        "https://splunk.example.test:8088/services/collector/event",
        "test-token",
        "security",
    )
    sink.send_triage(
        "tenant-a",
        {
            "event_id": "replay-001",
            "decision": "acknowledged",
            "reviewed_by": "analyst-a",
            "recorded_at": "2026-10-22T12:00:02Z",
            "evidence_refs": ["zeek://conn.log#replay-001"],
            "prediction": {"model_id": "m-test", "prediction": 1},
        },
        "triage-request-001",
    )
    triage_payload = json.loads(captured["request"].data)
    assert triage_payload["event"]["kind"] == "incident_triage"
    assert triage_payload["event"]["decision"] == "acknowledged"
    assert triage_payload["event"]["model_version"] == "m-test"
    assert triage_payload["event"]["correlation_id"] == "triage-request-001"
    assert triage_payload["event"]["evidence_refs"] == [
        "zeek://conn.log#replay-001"
    ]
    assert "features" not in triage_payload["event"]


def test_metrics_endpoint_exposes_prometheus_format(monkeypatch) -> None:
    with tenant_client(monkeypatch) as client:
        response = client.get("/metrics")

    assert response.status_code == 200
    assert "threat_detection_inference_duration_seconds" in response.text
    assert "threat_detection_model_info" in response.text


def test_ingestion_validation_errors_increment_metrics(monkeypatch) -> None:
    with tenant_client(monkeypatch) as client:
        metrics_before = client.get("/metrics").text
        event = sample_event()
        event["schema_version"] = "99.0.0"
        response = client.post(
            "/v1/ingest",
            json={"events": [event]},
            headers=bearer("tenant-a"),
        )
        metrics_after = client.get("/metrics").text

    def error_count(payload: str) -> float:
        return next(
            float(line.split()[-1])
            for line in payload.splitlines()
            if line.startswith("threat_detection_ingestion_errors_total ")
        )

    assert response.status_code == 422
    assert error_count(metrics_after) - error_count(metrics_before) == 1


def test_rate_limit_registry_has_a_bounded_tenant_capacity() -> None:
    limiter = TenantRateLimiter(limit=1, max_tenants=1)
    limiter.check("tenant-a")

    with pytest.raises(HTTPException, match="capacity is temporarily exhausted") as exc:
        limiter.check("tenant-b")
    assert exc.value.status_code == 503
