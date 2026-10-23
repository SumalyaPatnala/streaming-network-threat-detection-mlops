from __future__ import annotations

import json
import os
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.request import urlopen

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from threat_detection.api import DEFAULT_SCHEMA_PATH, SCHEMA_VERSION, create_app

ROOT = Path(__file__).resolve().parents[1]
MODEL_ID = "m-e938dbe02eac44609ef11145e7eaa535"
MODEL_PATH = Path(os.environ.get("MODEL_PATH", ROOT / "models" / "xgboost"))
if not (MODEL_PATH / "MLmodel").is_file():
    MODEL_PATH = (
        ROOT
        / "mlruns"
        / "1"
        / "models"
        / MODEL_ID
        / "artifacts"
    )


class StaticSigningKey:
    def __init__(self, key: Any) -> None:
        self.key = key


class MockHECHandler(BaseHTTPRequestHandler):
    events: ClassVar[list[dict[str, Any]]] = []
    authorization_headers: ClassVar[list[str]] = []
    failures_remaining = 0

    def do_POST(self) -> None:
        if self.path != "/services/collector/event":
            self.send_error(404)
            return
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).events.append(json.loads(body))
        type(self).authorization_headers.append(self.headers.get("Authorization", ""))
        if type(self).failures_remaining:
            type(self).failures_remaining -= 1
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"temporary HEC failure")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"text":"Success","code":0}')

    def log_message(self, _format: str, *args: object) -> None:
        return


def make_tls_certificate(tmp_path: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "mock-hec-cert.pem"
    private_key_path = tmp_path / "mock-hec-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    private_key_path.write_bytes(
        key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
    )
    return certificate_path, private_key_path


def event_body(event_id: str, duration: float | None = None) -> dict[str, Any]:
    names = json.loads(DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8"))[
        "properties"
    ]["features"]["required"]
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "observed_at": "2026-10-22T12:00:00Z",
        "features": {name: None for name in names} | {"duration": duration},
        "evidence_refs": [f"zeek://conn.log#{event_id}"],
    }


def signed_token(private_key, tenant_id: str, roles: list[str]) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": "https://localhost.test/issuer",
            "aud": "network-threat-api",
            "sub": f"{tenant_id}-operator",
            "tenant_id": tenant_id,
            "roles": roles,
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "local-demo-key"},
    )


@pytest.mark.skipif(
    not (MODEL_PATH / "MLmodel").is_file(),
    reason="downloaded local MLflow artifact is not present",
)
def test_saved_model_tenant_ingestion_splunk_drift_and_triage(
    monkeypatch, tmp_path
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    MockHECHandler.events = []
    MockHECHandler.authorization_headers = []
    MockHECHandler.failures_remaining = 1

    certificate_path, private_key_path = make_tls_certificate(tmp_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockHECHandler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certificate_path, private_key_path)
    server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    trusted_tls = ssl.create_default_context(cafile=str(certificate_path))
    original_urlopen = urlopen

    def trusted_urlopen(request, timeout):
        return original_urlopen(request, timeout=timeout, context=trusted_tls)

    monkeypatch.setattr("threat_detection.splunk.urlopen", trusted_urlopen)
    monkeypatch.setattr(
        "jwt.PyJWKClient.get_signing_key_from_jwt",
        lambda _client, _token: StaticSigningKey(private_key.public_key()),
    )
    drift_reference = tmp_path / "drift-reference.json"
    drift_reference.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "features": {
                    "duration": {
                        "kind": "numeric",
                        "boundaries": [1.0, 2.0],
                        "probabilities": [0.0, 1.0, 0.0],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    env = {
        "MODEL_PATH": str(MODEL_PATH),
        "MODEL_ID": MODEL_ID,
        "OIDC_ISSUER": "https://localhost.test/issuer",
        "OIDC_AUDIENCE": "network-threat-api",
        "OIDC_JWKS_URL": "https://localhost.test/jwks",
        "SPLUNK_HEC_URL": (
            f"https://localhost:{server.server_port}/services/collector/event"
        ),
        "SPLUNK_HEC_TOKEN": "test-only-secret",
        "SPLUNK_INDEX": "security-test",
        "DRIFT_REFERENCE_PATH": str(drift_reference),
        "DRIFT_PSI_THRESHOLD": "0.2",
        "DRIFT_WINDOW_SIZE": "2",
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    try:
        with TestClient(create_app()) as client:
            analyst = {
                "Authorization": f"Bearer {signed_token(private_key, 'tenant-a', ['events:write', 'analyst'])}",
                "X-Request-ID": "e2e-ingest-001",
            }
            writer = {
                "Authorization": f"Bearer {signed_token(private_key, 'tenant-a', ['events:write'])}"
            }
            other_tenant = {
                "Authorization": f"Bearer {signed_token(private_key, 'tenant-b', ['analyst'])}"
            }

            unauthenticated = client.post(
                "/v1/ingest", json={"events": [event_body("e2e-001")]}
            )
            assert unauthenticated.status_code == 401

            first = client.post(
                "/v1/ingest",
                json={"events": [event_body("e2e-001")]},
                headers=analyst,
            )
            assert first.status_code == 503
            assert "was stored" in first.json()["detail"]
            retry = client.post(
                "/v1/ingest",
                json={"events": [event_body("e2e-001")]},
                headers=analyst,
            )
            assert retry.status_code == 200, retry.text
            prediction = retry.json()[0]
            assert prediction["duplicate"] is True
            assert prediction["prediction"]["model_id"] == MODEL_ID
            assert prediction["prediction"]["prediction"] == 1
            assert prediction["evidence_refs"] == ["zeek://conn.log#e2e-001"]
            assert prediction["response_recommendation"] == "analyst_review"
            assert retry.headers["x-request-id"] == "e2e-ingest-001"

            malformed = event_body("e2e-invalid")
            malformed["schema_version"] = "99.0.0"
            rejected = client.post(
                "/v1/ingest",
                json={"events": [malformed]},
                headers=analyst,
            )
            assert rejected.status_code == 422

            conflict_body = event_body("e2e-001")
            conflict_body["features"]["proto"] = "udp"
            conflict = client.post(
                "/v1/ingest",
                json={"events": [conflict_body]},
                headers=analyst,
            )
            assert conflict.status_code == 409

            batch = client.post(
                "/v1/predict/batch",
                json={
                    "records": [
                        {
                            key: value
                            for key, value in event_body("batch-001").items()
                            if key != "evidence_refs"
                        }
                    ]
                },
                headers=analyst,
            )
            assert batch.status_code == 200, batch.text
            assert batch.json()["model_id"] == MODEL_ID
            assert len(batch.json()["predictions"]) == 1

            second = client.post(
                "/v1/ingest",
                json={"events": [event_body("e2e-002", duration=0.1)]},
                headers=analyst,
            )
            assert second.status_code == 200
            third = client.post(
                "/v1/ingest",
                json={"events": [event_body("e2e-003", duration=0.1)]},
                headers=analyst,
            )
            assert third.status_code == 200
            drift_status = client.get("/v1/monitoring/drift", headers=analyst)
            assert drift_status.status_code == 200
            assert drift_status.json()["status"] == "alert"

            hidden = client.get("/v1/events/e2e-001", headers=other_tenant)
            assert hidden.status_code == 404
            forbidden_triage = client.post(
                "/v1/incidents/e2e-001/triage",
                json={"decision": "acknowledged"},
                headers=writer,
            )
            assert forbidden_triage.status_code == 403

            triage = client.post(
                "/v1/incidents/e2e-001/triage",
                json={"decision": "acknowledged"},
                headers={
                    **analyst,
                    "X-Request-ID": "e2e-triage-001",
                },
            )
            assert triage.status_code == 200, triage.text
            visible = client.get("/v1/events/e2e-001", headers=analyst)
            assert visible.status_code == 200
            assert visible.json()["triage_history"][0]["reviewed_by"] == "tenant-a-operator"
            assert visible.json()["triage_history"][0]["decision"] == "acknowledged"

            metrics = client.get("/metrics")
            assert metrics.status_code == 200
            for metric in (
                "threat_detection_model_info",
                "threat_detection_inference_requests_total",
                "threat_detection_inference_duration_seconds_bucket",
                "threat_detection_ingested_events_total",
                "threat_detection_feature_drift_alert",
            ):
                assert metric in metrics.text
            assert f'model_id="{MODEL_ID}"' in metrics.text
            assert "tenant-a" not in metrics.text

        model_exports = [
            envelope["event"]
            for envelope in MockHECHandler.events
            if envelope["event"]["kind"] == "model_prediction"
        ]
        triage_exports = [
            envelope["event"]
            for envelope in MockHECHandler.events
            if envelope["event"]["kind"] == "incident_triage"
        ]
        assert len(model_exports) == 4
        assert all(event["tenant_id"] == "tenant-a" for event in model_exports)
        assert model_exports[0]["correlation_id"] == "e2e-ingest-001"
        assert model_exports[0]["model_version"] == MODEL_ID
        assert all("features" not in event for event in model_exports)
        assert len(triage_exports) == 1
        assert triage_exports[0]["correlation_id"] == "e2e-triage-001"
        assert triage_exports[0]["evidence_refs"] == ["zeek://conn.log#e2e-001"]
        assert all(
            header == "Splunk test-only-secret"
            for header in MockHECHandler.authorization_headers
        )
        assert all(
            "test-only-secret" not in json.dumps(envelope)
            for envelope in MockHECHandler.events
        )
        print(
            "saved-model e2e passed: OIDC signature/roles, prediction, "
            "HEC retry/export, schema rejection, idempotency, batch, drift, "
            "tenant isolation, human triage, and Prometheus metrics"
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
