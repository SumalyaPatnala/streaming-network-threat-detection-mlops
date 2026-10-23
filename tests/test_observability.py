from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_prometheus_alerts_use_exposed_metrics_without_tenant_labels() -> None:
    rules = yaml.safe_load(
        (ROOT / "deploy/observability/prometheus-alerts.yaml").read_text(
            encoding="utf-8"
        )
    )
    expressions = [
        rule["expr"]
        for group in rules["groups"]
        for rule in group["rules"]
    ]

    assert len(expressions) == 4
    assert any("threat_detection_inference_requests_total" in expr for expr in expressions)
    assert any("threat_detection_ingestion_errors_total" in expr for expr in expressions)
    assert any("threat_detection_feature_drift_alert" in expr for expr in expressions)
    assert any("threat_detection_splunk_delivery_errors_total" in expr for expr in expressions)
    assert all("tenant_id" not in expr for expr in expressions)


def test_grafana_dashboard_is_importable_and_has_latency_drift_panels() -> None:
    dashboard = json.loads(
        (ROOT / "deploy/observability/grafana-dashboard.json").read_text(
            encoding="utf-8"
        )
    )
    titles = {panel["title"] for panel in dashboard["panels"]}

    assert dashboard["uid"] == "network-threat-detection"
    assert "Inference latency p95" in titles
    assert "Maximum feature PSI across tenant windows" in titles
