from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import anyio
import mlflow.sklearn
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from threat_detection.drift import DriftMonitor, load_drift_monitor
from threat_detection.event_store import EventConflictError, EventStore
from threat_detection.identity import (
    AuthenticationError,
    IdentityProviderUnavailableError,
    OIDCVerifier,
    TenantPrincipal,
)
from threat_detection.observability import (
    INFERENCE_LATENCY,
    INFERENCE_REQUESTS,
    INGESTED_EVENTS,
    INGESTION_ERRORS,
    SPLUNK_DELIVERY_ERRORS,
    prometheus_payload,
)
from threat_detection.splunk import SplunkDeliveryError, SplunkHECSink

LOGGER = logging.getLogger(__name__)
SCHEMA_VERSION = "1.0.0"
CLASSIFICATION_THRESHOLD = 0.5
MAX_BATCH_SIZE = 32
MAX_REQUEST_BYTES = 256 * 1024
MAX_INGEST_EVENTS_PER_MINUTE = 120
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
EVIDENCE_REFERENCE = Annotated[StrictStr, Field(min_length=1, max_length=256)]
DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "network-flow-model-input-v1.schema.json"
)


class NetworkFlowFeatures(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    dst_port: Annotated[StrictInt, Field(ge=0, le=65535)] | None
    proto: StrictStr | None
    service: StrictStr | None
    duration: StrictFloat | StrictInt | None
    src_bytes: Annotated[StrictInt, Field(ge=0)] | None
    dst_bytes: Annotated[StrictInt, Field(ge=0)] | None
    conn_state: StrictStr | None
    missed_bytes: Annotated[StrictInt, Field(ge=0)] | None
    src_pkts: Annotated[StrictInt, Field(ge=0)] | None
    src_ip_bytes: Annotated[StrictInt, Field(ge=0)] | None
    dst_pkts: Annotated[StrictInt, Field(ge=0)] | None
    dst_ip_bytes: Annotated[StrictInt, Field(ge=0)] | None
    dns_qclass: Annotated[StrictInt, Field(ge=0)] | None
    dns_qtype: Annotated[StrictInt, Field(ge=0)] | None
    dns_rcode: Annotated[StrictInt, Field(ge=0)] | None
    dns_AA: StrictStr | None
    dns_RD: StrictStr | None
    dns_RA: StrictStr | None
    dns_rejected: StrictStr | None
    ssl_version: StrictStr | None
    ssl_cipher: StrictStr | None
    ssl_resumed: StrictStr | None
    ssl_established: StrictStr | None
    http_trans_depth: StrictFloat | StrictInt | None
    http_method: StrictStr | None
    http_version: StrictFloat | StrictInt | None
    http_request_body_len: Annotated[StrictInt, Field(ge=0)] | None
    http_response_body_len: Annotated[StrictInt, Field(ge=0)] | None
    http_status_code: Annotated[StrictInt, Field(ge=0, le=599)] | None
    weird_notice: StrictStr | None

    @field_validator("duration", "http_trans_depth", "http_version")
    @classmethod
    def require_finite_numeric_values(cls, value: float | None) -> float | int | None:
        if value is not None and not np.isfinite(value):
            raise ValueError("numeric feature values must be finite")
        return value


class PredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    schema_version: Literal["1.0.0"]
    event_id: Annotated[StrictStr, Field(min_length=1, max_length=128)] | None = None
    observed_at: datetime | None = Field(default=None, strict=False)
    features: NetworkFlowFeatures

    @field_validator("observed_at")
    @classmethod
    def require_timezone_for_observation_time(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class BatchPredictionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    records: Annotated[
        list[PredictionRequest],
        Field(min_length=1, max_length=MAX_BATCH_SIZE),
    ]


class PredictionResponse(BaseModel):
    event_id: str | None
    observed_at: datetime | None
    prediction: Literal[0, 1]
    class_label: Literal["normal", "attack"]
    predicted_at: datetime | None = None
    model_score: Annotated[
        float,
        Field(
            ge=0,
            le=1,
            description=(
                "Uncalibrated positive-class model probability; not a calibrated "
                "threat-risk estimate."
            ),
        ),
    ]
    threshold: float
    model_id: str
    schema_version: str
    evidence_refs: list[str] | None = None


class BatchPredictionResponse(BaseModel):
    predictions: list[PredictionResponse]
    model_id: str
    schema_version: str


class IngestEvent(PredictionRequest):
    event_id: Annotated[StrictStr, Field(min_length=1, max_length=128)]
    observed_at: datetime = Field(strict=False)
    evidence_refs: Annotated[
        list[EVIDENCE_REFERENCE], Field(min_length=1, max_length=8)
    ]


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    events: Annotated[list[IngestEvent], Field(min_length=1, max_length=MAX_BATCH_SIZE)]


class IngestResult(BaseModel):
    event_id: str
    prediction: PredictionResponse
    evidence_refs: list[str]
    ingested_at: datetime
    duplicate: bool
    triage_status: Literal["open", "acknowledged", "dismissed"]
    triage_history: list[TriageAuditEntry]
    response_recommendation: Literal["none", "analyst_review"]


class TriageAuditEntry(BaseModel):
    decision: Literal["acknowledged", "dismissed"]
    reviewed_by: str
    recorded_at: datetime


class TriageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    decision: Literal["acknowledged", "dismissed"]


class TriageResponse(BaseModel):
    event_id: str
    decision: Literal["acknowledged", "dismissed"]
    reviewed_by: str
    recorded_at: datetime


class TenantRateLimiter:
    def __init__(
        self,
        limit: int = MAX_INGEST_EVENTS_PER_MINUTE,
        max_tenants: int = 2048,
    ) -> None:
        self.limit = limit
        self.max_tenants = max_tenants
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = {}

    def check(self, tenant_id: str, amount: int = 1) -> None:
        now = time.monotonic()
        with self._lock:
            recent = [
                timestamp
                for timestamp in self._events.get(tenant_id, [])
                if now - timestamp < 60
            ]
            self._events = {
                tenant: timestamps
                for tenant, timestamps in self._events.items()
                if tenant == tenant_id
                or any(now - timestamp < 60 for timestamp in timestamps)
            }
            if tenant_id not in self._events and len(self._events) >= self.max_tenants:
                raise HTTPException(
                    status_code=503,
                    detail="Tenant rate-limit capacity is temporarily exhausted",
                )
            if len(recent) + amount > self.limit:
                self._events[tenant_id] = recent
                raise HTTPException(status_code=429, detail="Tenant ingestion quota exceeded")
            recent.extend([now] * amount)
            self._events[tenant_id] = recent


class PredictiveModel(Protocol):
    def predict_proba(self, features: pd.DataFrame) -> np.ndarray: ...


@dataclass(frozen=True)
class ModelRuntime:
    model: PredictiveModel
    feature_names: tuple[str, ...]
    model_id: str
    schema_version: str


def load_model_runtime(
    model_path: Path,
    model_id: str,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
) -> ModelRuntime:
    if not model_id.strip():
        raise ValueError("MODEL_ID must identify the explicitly selected model artifact")
    if not model_path.is_dir() or not (model_path / "MLmodel").is_file():
        raise FileNotFoundError(
            f"MLflow model artifact is missing or incomplete: {model_path}"
        )
    if not schema_path.is_file():
        raise FileNotFoundError(f"Model input schema is missing: {schema_path}")

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError(f"Unable to read model input schema: {schema_path}") from error

    if not isinstance(schema, dict):
        raise TypeError(f"Model input schema must be a JSON object: {schema_path}")
    version = schema.get("properties", {}).get("schema_version", {}).get("const")
    feature_schema = schema.get("properties", {}).get("features", {})
    feature_names = feature_schema.get("required")
    feature_properties = feature_schema.get("properties", {})
    if version != SCHEMA_VERSION:
        raise ValueError(
            f"Incompatible input schema version {version!r}; expected {SCHEMA_VERSION!r}"
        )
    if (
        not isinstance(feature_names, list)
        or len(feature_names) != 30
        or set(feature_names) != set(feature_properties)
        or feature_schema.get("additionalProperties") is not False
    ):
        raise ValueError("Input schema does not define the expected closed 30-feature contract")

    try:
        model = mlflow.sklearn.load_model(str(model_path))
    except Exception as error:
        raise RuntimeError(f"Unable to load selected MLflow model at {model_path}") from error

    steps = getattr(model, "named_steps", None)
    if not isinstance(steps, Mapping) or not {"preprocessor", "classifier"} <= set(steps):
        raise ValueError("Loaded model must be a fitted preprocessing/classifier pipeline")
    if type(steps["classifier"]).__name__ != "XGBClassifier":
        raise ValueError("Selected model artifact is not an XGBoost classifier")
    fitted_features = getattr(steps["preprocessor"], "feature_names_in_", None)
    if fitted_features is None or tuple(fitted_features) != tuple(feature_names):
        raise ValueError(
            "Model feature names/order do not match the versioned input schema"
        )
    classes = getattr(steps["classifier"], "classes_", None)
    if classes is None or not np.array_equal(np.asarray(classes), np.asarray([0, 1])):
        raise ValueError("Loaded XGBoost model does not expose expected classes [0, 1]")
    if not callable(getattr(model, "predict_proba", None)):
        raise TypeError("Loaded model does not implement predict_proba")

    return ModelRuntime(
        model=model,
        feature_names=tuple(feature_names),
        model_id=model_id,
        schema_version=version,
    )


class PredictionService:
    """Reusable normalized-record inference independent of HTTP transport."""

    def __init__(
        self,
        runtime: ModelRuntime,
        threshold: float = CLASSIFICATION_THRESHOLD,
    ) -> None:
        if not 0 <= threshold <= 1:
            raise ValueError("classification threshold must be within [0, 1]")
        self.runtime = runtime
        self.threshold = threshold

    def predict(
        self,
        record: PredictionRequest,
    ) -> PredictionResponse:
        feature_values = record.features.model_dump()
        row = pd.DataFrame(
            [[feature_values[name] for name in self.runtime.feature_names]],
            columns=self.runtime.feature_names,
        )
        try:
            with INFERENCE_LATENCY.time():
                scores = np.asarray(self.runtime.model.predict_proba(row))
        except Exception as error:
            INFERENCE_REQUESTS.labels(outcome="error").inc()
            LOGGER.exception("Model inference failed")
            raise RuntimeError("Model inference failed") from error
        if (
            scores.shape != (1, 2)
            or not np.isfinite(scores).all()
            or np.any((scores < 0) | (scores > 1))
            or not np.allclose(scores.sum(axis=1), 1.0, rtol=0, atol=1e-6)
        ):
            INFERENCE_REQUESTS.labels(outcome="error").inc()
            raise RuntimeError("Model returned an invalid binary probability matrix")
        score = float(scores[0, 1])
        prediction = int(score >= self.threshold)
        INFERENCE_REQUESTS.labels(outcome="attack" if prediction else "normal").inc()
        return PredictionResponse(
            event_id=record.event_id,
            observed_at=record.observed_at,
            prediction=prediction,
            class_label="attack" if prediction else "normal",
            model_score=score,
            threshold=self.threshold,
            model_id=self.runtime.model_id,
            schema_version=self.runtime.schema_version,
        )

    def predict_many(
        self,
        records: list[PredictionRequest],
    ) -> list[PredictionResponse]:
        return [self.predict(record) for record in records]


class PayloadLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (
                value.decode("latin-1")
                for name, value in scope.get("headers", [])
                if name.lower() == b"content-length"
            ),
            None,
        )
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                await self._reject(send, 400, "Invalid Content-Length")
                return
            if declared_length > self.max_bytes:
                await self._reject(send, 413, "Request body exceeds the size limit")
                return

        messages: list[Message] = []
        total_bytes = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                total_bytes += len(message.get("body", b""))
                if total_bytes > self.max_bytes:
                    await self._reject(send, 413, "Request body exceeds the size limit")
                    return
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                return

        async def replay() -> Message:
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    @staticmethod
    async def _reject(send: Send, status_code: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_app(
    runtime_loader: Callable[[Path, str, Path], ModelRuntime] = load_model_runtime,
    identity_verifier_factory: Callable[[], OIDCVerifier | None] = (
        OIDCVerifier.from_environment
    ),
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        model_path_value = os.environ.get("MODEL_PATH")
        model_id = os.environ.get("MODEL_ID")
        if not model_path_value:
            raise RuntimeError("MODEL_PATH must point to an explicitly selected model artifact")
        if not model_id:
            raise RuntimeError("MODEL_ID must identify the explicitly selected model artifact")
        schema_path = Path(
            os.environ.get("MODEL_SCHEMA_PATH", str(DEFAULT_SCHEMA_PATH))
        )
        application.state.runtime = runtime_loader(
            Path(model_path_value), model_id, schema_path
        )
        application.state.prediction_service = PredictionService(
            application.state.runtime
        )
        application.state.identity_verifier = identity_verifier_factory()
        application.state.event_store = EventStore(
            os.environ.get("EVENT_STORE_PATH", ":memory:")
        )
        application.state.splunk_sink = SplunkHECSink.from_environment()
        application.state.tenant_rate_limiter = TenantRateLimiter()
        application.state.drift_monitor = load_drift_monitor(
            application.state.runtime.feature_names,
            threshold=float(os.environ.get("DRIFT_PSI_THRESHOLD", "0.2")),
            window_size=int(os.environ.get("DRIFT_WINDOW_SIZE", "100")),
        )
        yield
        application.state.event_store.close()
        application.state.prediction_service = None
        application.state.runtime = None

    application = FastAPI(
        title="Streaming Network Threat Detection API",
        version="1.0.0",
        description=(
            "Serves the versioned TON_IoT network-flow model. model_score is an "
            "uncalibrated classifier probability, not calibrated threat risk."
        ),
        lifespan=lifespan,
    )
    application.add_middleware(PayloadLimitMiddleware)

    @application.exception_handler(RequestValidationError)
    async def invalid_request(
        request: Request, error: RequestValidationError
    ) -> Response:
        if request.url.path == "/v1/ingest":
            INGESTION_ERRORS.inc()
        return Response(
            content=json.dumps({"detail": jsonable_encoder(error.errors())}),
            status_code=422,
            media_type="application/json",
        )

    @application.middleware("http")
    async def correlate_and_log(request: Request, call_next) -> Response:
        supplied_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_id if REQUEST_ID_PATTERN.fullmatch(supplied_id) else str(uuid.uuid4())
        )
        request.state.request_id = request_id
        started_at = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        LOGGER.info(
            json.dumps(
                {
                    "event": "http_request",
                    "request_id": request_id,
                    "method": request.method,
                    "status_code": response.status_code,
                    "duration_ms": round((time.perf_counter() - started_at) * 1000, 3),
                },
                separators=(",", ":"),
            )
        )
        return response

    async def authenticate(
        request: Request,
        *,
        required_role: str | None = None,
        require_tenant: bool = False,
    ) -> TenantPrincipal | None:
        verifier: OIDCVerifier | None = getattr(
            request.app.state, "identity_verifier", None
        )
        if verifier is None:
            if require_tenant:
                raise HTTPException(
                    status_code=503,
                    detail="Tenant-authenticated operations are not configured",
                )
            return None
        authorization = request.headers.get("authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token:
            raise HTTPException(
                status_code=401,
                detail="A valid bearer token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            principal = await anyio.to_thread.run_sync(verifier.verify, token)
        except IdentityProviderUnavailableError as error:
            raise HTTPException(
                status_code=503,
                detail="Identity provider signing keys are temporarily unavailable",
            ) from error
        except AuthenticationError as error:
            raise HTTPException(
                status_code=401,
                detail="A valid bearer token is required",
                headers={"WWW-Authenticate": "Bearer"},
            ) from error
        if required_role is not None and not {
            required_role,
            "admin",
        }.intersection(principal.roles):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return principal

    def prediction_service(request: Request) -> PredictionService:
        service: PredictionService | None = getattr(
            request.app.state, "prediction_service", None
        )
        if service is None:
            raise HTTPException(status_code=503, detail="Model is not ready")
        return service

    def event_result(record: dict[str, Any], duplicate: bool) -> IngestResult:
        prediction = PredictionResponse.model_validate(record["prediction"])
        return IngestResult(
            event_id=record["event_id"],
            prediction=prediction,
            evidence_refs=record["evidence_refs"],
            ingested_at=record["ingested_at"],
            duplicate=duplicate,
            triage_status=record["triage_status"],
            triage_history=record["triage_history"],
            response_recommendation=(
                "analyst_review" if prediction.prediction == 1 else "none"
            ),
        )

    @application.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "alive"}

    @application.get("/health/ready")
    async def ready(request: Request) -> dict[str, str]:
        if getattr(request.app.state, "prediction_service", None) is None:
            raise HTTPException(status_code=503, detail="Model is not ready")
        return {"status": "ready"}

    @application.get("/v1/model/info")
    async def model_info(request: Request) -> dict[str, Any]:
        await authenticate(request)
        service = prediction_service(request)
        return {
            "model_id": service.runtime.model_id,
            "schema_version": service.runtime.schema_version,
            "threshold": service.threshold,
            "score_semantics": "uncalibrated positive-class model probability",
            "feature_count": len(service.runtime.feature_names),
        }

    @application.post(
        "/v1/predict",
        response_model=PredictionResponse,
        response_model_exclude_none=True,
    )
    async def predict(record: PredictionRequest, request: Request) -> PredictionResponse:
        await authenticate(request)
        service = prediction_service(request)
        try:
            return await anyio.to_thread.run_sync(service.predict, record)
        except RuntimeError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    @application.post(
        "/v1/predict/batch",
        response_model=BatchPredictionResponse,
        response_model_exclude_none=True,
    )
    async def predict_batch(
        batch: BatchPredictionRequest, request: Request
    ) -> BatchPredictionResponse:
        await authenticate(request)
        service = prediction_service(request)
        try:
            predictions = await anyio.to_thread.run_sync(
                service.predict_many, batch.records
            )
        except RuntimeError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error
        return BatchPredictionResponse(
            predictions=predictions,
            model_id=service.runtime.model_id,
            schema_version=service.runtime.schema_version,
        )

    @application.post("/v1/ingest", response_model=list[IngestResult])
    async def ingest(batch: IngestRequest, request: Request) -> list[IngestResult]:
        principal = await authenticate(
            request, required_role="events:write", require_tenant=True
        )
        assert principal is not None
        request.app.state.tenant_rate_limiter.check(
            principal.tenant_id, amount=len(batch.events)
        )
        service = prediction_service(request)
        store: EventStore = request.app.state.event_store
        sink: SplunkHECSink | None = request.app.state.splunk_sink
        results: list[IngestResult] = []

        for event in batch.events:
            event_body = event.model_dump(mode="json")
            payload_digest = sha256(
                json.dumps(
                    event_body, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            try:
                stored = store.lookup(
                    principal.tenant_id, event.event_id, payload_digest
                )
                created = False
                if stored is None:
                    prediction_input = PredictionRequest.model_validate(
                        event.model_dump(exclude={"evidence_refs"})
                    )
                    prediction = (
                        await anyio.to_thread.run_sync(
                            service.predict, prediction_input
                        )
                    ).model_copy(
                        update={
                            "predicted_at": datetime.now(UTC),
                            "evidence_refs": event.evidence_refs,
                        }
                    )
                    stored, created = store.insert(
                        tenant_id=principal.tenant_id,
                        event_id=event.event_id,
                        payload_digest=payload_digest,
                        prediction=prediction.model_dump(mode="json"),
                        evidence_refs=event.evidence_refs,
                        ingested_at=datetime.now(UTC).isoformat(),
                    )
                    if created and request.app.state.drift_monitor is not None:
                        request.app.state.drift_monitor.observe(
                            principal.tenant_id,
                            event.features.model_dump(),
                        )
                if sink is not None and store.claim_splunk_delivery(
                    principal.tenant_id, event.event_id
                ):
                    try:
                        await anyio.to_thread.run_sync(
                            sink.send, principal.tenant_id, stored
                        )
                    except SplunkDeliveryError as error:
                        store.finish_splunk_delivery(
                            principal.tenant_id, event.event_id, succeeded=False
                        )
                        INGESTION_ERRORS.inc()
                        SPLUNK_DELIVERY_ERRORS.inc()
                        LOGGER.warning(
                            "Splunk event delivery failed request_id=%s",
                            request.state.request_id,
                        )
                        raise HTTPException(
                            status_code=503,
                            detail="Event prediction was stored but Splunk delivery failed",
                        ) from error
                    store.finish_splunk_delivery(
                        principal.tenant_id, event.event_id, succeeded=True
                    )
                results.append(event_result(stored, duplicate=not created))
                INGESTED_EVENTS.labels(
                    outcome="duplicate" if not created else "accepted"
                ).inc()
            except EventConflictError as error:
                INGESTION_ERRORS.inc()
                raise HTTPException(status_code=409, detail=str(error)) from error

        return results

    @application.get("/v1/events/{event_id}", response_model=IngestResult)
    async def get_event(event_id: str, request: Request) -> IngestResult:
        principal = await authenticate(
            request, required_role="analyst", require_tenant=True
        )
        assert principal is not None
        record = request.app.state.event_store.get(principal.tenant_id, event_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return event_result(record, duplicate=False)

    @application.get("/v1/incidents", response_model=list[IngestResult])
    async def list_incidents(request: Request, limit: int = 50) -> list[IngestResult]:
        if not 1 <= limit <= 100:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
        principal = await authenticate(
            request, required_role="analyst", require_tenant=True
        )
        assert principal is not None
        records = request.app.state.event_store.list_incidents(
            principal.tenant_id, limit
        )
        return [event_result(record, duplicate=False) for record in records]

    @application.post(
        "/v1/incidents/{event_id}/triage", response_model=TriageResponse
    )
    async def triage_incident(
        event_id: str, body: TriageRequest, request: Request
    ) -> TriageResponse:
        principal = await authenticate(
            request, required_role="analyst", require_tenant=True
        )
        assert principal is not None
        recorded_at = datetime.now(UTC)
        record = request.app.state.event_store.triage(
            tenant_id=principal.tenant_id,
            event_id=event_id,
            decision=body.decision,
            reviewed_by=principal.subject,
            recorded_at=recorded_at.isoformat(),
        )
        if record is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        sink: SplunkHECSink | None = request.app.state.splunk_sink
        if sink is not None:
            try:
                await anyio.to_thread.run_sync(
                    sink.send_triage,
                    principal.tenant_id,
                    {
                        "event_id": event_id,
                        "decision": body.decision,
                        "reviewed_by": principal.subject,
                        "recorded_at": recorded_at.isoformat(),
                        "evidence_refs": record["evidence_refs"],
                        "prediction": record["prediction"],
                    },
                )
            except SplunkDeliveryError as error:
                INGESTION_ERRORS.inc()
                SPLUNK_DELIVERY_ERRORS.inc()
                LOGGER.warning(
                    "Splunk triage delivery failed request_id=%s",
                    request.state.request_id,
                )
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Triage decision was recorded but Splunk delivery failed; "
                        "repeat the triage request to retry delivery"
                    ),
                ) from error
        LOGGER.info(
            json.dumps(
                {
                    "event": "incident_triaged",
                    "request_id": request.state.request_id,
                    "decision": body.decision,
                },
                separators=(",", ":"),
            )
        )
        return TriageResponse(
            event_id=event_id,
            decision=body.decision,
            reviewed_by=principal.subject,
            recorded_at=recorded_at,
        )

    @application.get("/v1/monitoring/drift")
    async def drift_status(request: Request) -> dict[str, Any]:
        principal = await authenticate(
            request, required_role="analyst", require_tenant=True
        )
        assert principal is not None
        monitor: DriftMonitor | None = request.app.state.drift_monitor
        if monitor is None:
            return {
                "status": "not_configured",
                "detail": "No validated DRIFT_REFERENCE_PATH is configured",
            }
        return monitor.status(principal.tenant_id)

    @application.get("/metrics")
    async def metrics() -> Response:
        payload, content_type = prometheus_payload()
        return Response(content=payload, media_type=content_type)

    return application


app = create_app()
