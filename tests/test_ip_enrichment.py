
from scripts.enrich_alerts import classify_ip, enrich_alert, enrich_alerts


def test_public_ip():
    result = classify_ip("8.8.8.8")
    assert result["classification"] == "public"
    assert result["globally_routable"] is True


def test_private_ip():
    result = classify_ip("192.168.1.10")
    assert result["classification"] == "private"


def test_documentation_ip():
    result = classify_ip("203.0.113.10")
    assert result["classification"] == "documentation"
    assert result["globally_routable"] is False


def test_loopback_ip():
    result = classify_ip("127.0.0.1")
    assert result["classification"] == "loopback"


def test_invalid_ip():
    result = classify_ip("not-an-ip")
    assert result["classification"] == "invalid"


def test_missing_ip():
    result = classify_ip(None)
    assert result["classification"] == "unknown"


def test_enrich_alert_preserves_original_fields():
    alert = {
        "alert_type": "windows_password_spraying",
        "source_ip": "203.0.113.10",
        "severity": "high",
    }

    enriched = enrich_alert(alert)

    assert enriched["severity"] == "high"
    assert enriched["ip_context"]["classification"] == "documentation"
    assert enriched["geolocation"] == "not_checked"
    assert enriched["external_reputation"] == "not_checked"


def test_enrich_multiple_alerts():
    alerts = [
        {"source_ip": "8.8.8.8"},
        {"source_ip": "192.168.1.10"},
    ]

    results = enrich_alerts(alerts)

    assert len(results) == 2
    assert results[0]["ip_context"]["classification"] == "public"
    assert results[1]["ip_context"]["classification"] == "private"
