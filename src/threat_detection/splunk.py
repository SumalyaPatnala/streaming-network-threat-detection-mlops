from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class SplunkDeliveryError(RuntimeError):
    pass


class SplunkHECSink:
    def __init__(self, endpoint: str, token: str, index: str | None = None) -> None:
        parsed = urlparse(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not token.strip()
        ):
            raise ValueError("Splunk HEC requires an HTTPS endpoint and a token")
        self.endpoint = endpoint
        self.token = token
        self.index = index

    @classmethod
    def from_environment(cls) -> SplunkHECSink | None:
        endpoint = os.environ.get("SPLUNK_HEC_URL")
        token = os.environ.get("SPLUNK_HEC_TOKEN")
        index = os.environ.get("SPLUNK_INDEX")
        if not endpoint and not token:
            if index:
                raise RuntimeError("SPLUNK_INDEX requires Splunk HEC configuration")
            return None
        if not endpoint or not token:
            raise RuntimeError("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN must be set together")
        return cls(endpoint, token, index)

    def send(self, tenant_id: str, record: dict[str, Any]) -> None:
        prediction = record["prediction"]
        event = {
            "kind": "model_prediction",
            "tenant_id": tenant_id,
            "event_id": record["event_id"],
            "observed_at": prediction.get("observed_at"),
            "predicted_at": prediction["predicted_at"],
            "model_id": prediction["model_id"],
            "schema_version": prediction["schema_version"],
            "prediction": prediction["prediction"],
            "class_label": prediction["class_label"],
            "model_score": prediction["model_score"],
            "score_semantics": "uncalibrated positive-class model probability",
            "threshold": prediction["threshold"],
            "evidence_refs": record["evidence_refs"],
            "response_recommendation": (
                "analyst_review" if prediction["prediction"] == 1 else "none"
            ),
        }
        self._post(event, prediction["predicted_at"])

    def send_triage(self, tenant_id: str, record: dict[str, Any]) -> None:
        prediction = record["prediction"]
        event = {
            "kind": "incident_triage",
            "tenant_id": tenant_id,
            "event_id": record["event_id"],
            "decision": record["decision"],
            "reviewed_by": record["reviewed_by"],
            "recorded_at": record["recorded_at"],
            "model_id": prediction["model_id"],
            "prediction": prediction["prediction"],
            "evidence_refs": record["evidence_refs"],
        }
        self._post(event, record["recorded_at"])

    def _post(self, event: dict[str, Any], timestamp: str) -> None:
        hec_event: dict[str, Any] = {
            "time": datetime.fromisoformat(timestamp).timestamp(),
            "source": "network-threat-detection",
            "sourcetype": "_json",
            "event": event,
        }
        if self.index:
            hec_event["index"] = self.index
        request = Request(
            self.endpoint,
            data=json.dumps(hec_event, separators=(",", ":")).encode("utf-8"),
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:
                if not 200 <= response.status < 300:
                    raise SplunkDeliveryError("Splunk HEC returned a non-success status")
                result = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            raise SplunkDeliveryError("Splunk HEC delivery failed") from error
        if not isinstance(result, dict) or result.get("code") != 0:
            raise SplunkDeliveryError("Splunk HEC rejected the event")
