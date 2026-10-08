"""Every metric referenced by dashboards/alerts.yml must be registered by the service."""

import os
import re
import yaml
from prometheus_client import REGISTRY

import src.observability.metrics  # noqa: F401  (registers the metrics)

ALERTS_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboards", "alerts.yml")
METRIC_NAME = re.compile(r"\bforti_[a-z0-9_]+")


def _registered_names():
    names = set()
    for family in REGISTRY.collect():
        names.add(family.name)
        for sample in family.samples:
            names.add(sample.name)
    return names


def test_alert_rules_reference_registered_metrics():
    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    registered = _registered_names()
    exprs = [rule["expr"] for group in doc["groups"] for rule in group["rules"]]
    assert exprs, "alerts.yml defines no rules"
    for expr in exprs:
        referenced = METRIC_NAME.findall(expr)
        assert referenced, f"no forti_ metric in expr: {expr}"
        for name in referenced:
            assert name in registered, f"{name} (from expr {expr!r}) is not a registered metric"


def test_alert_rules_cover_model_degradation():
    with open(ALERTS_PATH, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    exprs = " ".join(rule["expr"] for group in doc["groups"] for rule in group["rules"])
    assert "forti_model_consecutive_failures" in exprs
