
import json

from scripts.generate_alerts import severity_for, THRESHOLD


def test_high_severity():
    assert severity_for(0.70) == "high"
    assert severity_for(0.95) == "high"


def test_medium_severity():
    assert severity_for(0.50) == "medium"
    assert severity_for(0.69) == "medium"


def test_low_severity():
    assert severity_for(0.40) == "low"
    assert severity_for(0.49) == "low"


def test_threshold_is_expected():
    assert THRESHOLD == 0.40


def test_alert_report_is_valid_json():
    from pathlib import Path

    report_path = Path("reports/ml_alerts.json")
    assert report_path.exists()

    report = json.loads(report_path.read_text())

    assert report["threshold"] == THRESHOLD
    assert isinstance(report["alerts"], list)
    assert report["alert_count"] == len(report["alerts"])

    for alert in report["alerts"]:
        assert alert["predicted_label"] == "attack"
        assert 0.0 <= alert["attack_probability"] <= 1.0
        assert alert["severity"] in {"low", "medium", "high"}
