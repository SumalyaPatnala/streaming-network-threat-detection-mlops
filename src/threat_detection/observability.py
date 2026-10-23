from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

INFERENCE_REQUESTS = Counter(
    "threat_detection_inference_requests_total",
    "Inference requests by model and result class",
    ["model_id", "outcome"],
)
INGESTED_EVENTS = Counter(
    "threat_detection_ingested_events_total",
    "Ingestion events by processing outcome",
    ["outcome"],
)
INGESTION_ERRORS = Counter(
    "threat_detection_ingestion_errors_total",
    "Malformed or failed ingestion events",
)
SPLUNK_DELIVERY_ERRORS = Counter(
    "threat_detection_splunk_delivery_errors_total",
    "Splunk HEC delivery failures",
)
INFERENCE_LATENCY = Histogram(
    "threat_detection_inference_duration_seconds",
    "Model inference latency in seconds by model",
    ["model_id"],
)
MODEL_INFO = Gauge(
    "threat_detection_model_info",
    "Loaded model identity and schema version",
    ["model_id", "schema_version"],
)
DRIFT_FEATURE_PSI = Gauge(
    "threat_detection_feature_drift_psi",
    "Maximum feature PSI across configured tenant windows",
    ["feature"],
)
DRIFT_FEATURE_ALERT = Gauge(
    "threat_detection_feature_drift_alert",
    "Whether any configured tenant window exceeded the feature drift threshold",
    ["feature"],
)


def prometheus_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
