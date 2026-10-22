from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import mlflow.sklearn
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
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

LOGGER = logging.getLogger(__name__)
SCHEMA_VERSION = "1.0.0"
CLASSIFICATION_THRESHOLD = 0.5
MAX_BATCH_SIZE = 32
MAX_REQUEST_BYTES = 256 * 1024
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


class BatchPredictionResponse(BaseModel):
    predictions: list[PredictionResponse]
    model_id: str
    schema_version: str


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
            scores = np.asarray(self.runtime.model.predict_proba(row))
        except Exception as error:
            LOGGER.exception("Model inference failed")
            raise RuntimeError("Model inference failed") from error
        if (
            scores.shape != (1, 2)
            or not np.isfinite(scores).all()
            or np.any((scores < 0) | (scores > 1))
            or not np.allclose(scores.sum(axis=1), 1.0, rtol=0, atol=1e-6)
        ):
            raise RuntimeError("Model returned an invalid binary probability matrix")
        score = float(scores[0, 1])
        prediction = int(score >= self.threshold)
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
        yield
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
        service: PredictionService | None = getattr(
            request.app.state, "prediction_service", None
        )
        if service is None:
            raise HTTPException(status_code=503, detail="Model is not ready")
        return {
            "model_id": service.runtime.model_id,
            "schema_version": service.runtime.schema_version,
            "threshold": service.threshold,
            "score_semantics": "uncalibrated positive-class model probability",
            "feature_count": len(service.runtime.feature_names),
        }

    @application.post("/v1/predict", response_model=PredictionResponse)
    async def predict(record: PredictionRequest, request: Request) -> PredictionResponse:
        service: PredictionService | None = getattr(
            request.app.state, "prediction_service", None
        )
        if service is None:
            raise HTTPException(status_code=503, detail="Model is not ready")
        try:
            return service.predict(record)
        except RuntimeError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    @application.post("/v1/predict/batch", response_model=BatchPredictionResponse)
    async def predict_batch(
        batch: BatchPredictionRequest, request: Request
    ) -> BatchPredictionResponse:
        service: PredictionService | None = getattr(
            request.app.state, "prediction_service", None
        )
        if service is None:
            raise HTTPException(status_code=503, detail="Model is not ready")
        try:
            predictions = service.predict_many(batch.records)
        except RuntimeError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error
        return BatchPredictionResponse(
            predictions=predictions,
            model_id=service.runtime.model_id,
            schema_version=service.runtime.schema_version,
        )

    return application


app = create_app()
