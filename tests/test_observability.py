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
    model_panels = [
        panel for panel in dashboard["panels"] if panel["title"] == "Inference throughput by outcome"
    ]
    assert "model_id" in model_panels[0]["targets"][0]["expr"]
    assert all(
        panel["datasource"]["uid"] == "prometheus"
        for panel in dashboard["panels"]
    )


def test_local_prometheus_and_grafana_compose_is_loopback_only_and_provisioned() -> None:
    compose = yaml.safe_load(
        (ROOT / "deploy/observability/docker-compose.yml").read_text(
            encoding="utf-8"
        )
    )
    prometheus = compose["services"]["prometheus"]
    grafana = compose["services"]["grafana"]

    assert prometheus["ports"] == ["127.0.0.1:19090:9090"]
    assert grafana["ports"] == ["127.0.0.1:13000:3000"]
    assert "GRAFANA_ADMIN_PASSWORD" in grafana["environment"]["GF_SECURITY_ADMIN_PASSWORD"]
    assert any("prometheus-alerts.yaml" in volume for volume in prometheus["volumes"])
    assert any("grafana-dashboard.json" in volume for volume in grafana["volumes"])
