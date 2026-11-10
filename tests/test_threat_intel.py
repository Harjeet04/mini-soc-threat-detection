from unittest.mock import Mock, patch

from scripts.threat_intel import (
    check_ip_reputation,
    _check_cached,
)


def setup_function():
    _check_cached.cache_clear()


def test_private_ip_is_skipped(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)

    result = check_ip_reputation("192.168.1.10")

    assert result["status"] == "skipped"


def test_missing_api_key(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")

    result = check_ip_reputation("8.8.8.8")

    assert result["status"] == "not_configured"


@patch("scripts.threat_intel.requests.get")
def test_successful_reputation_lookup(mock_get, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake_test_key")

    mock_response = Mock()
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 75,
            "totalReports": 20,
            "lastReportedAt": "2026-11-01T10:00:00+00:00",
            "countryCode": "US",
            "isp": "Example ISP",
        }
    }

    mock_get.return_value = mock_response

    result = check_ip_reputation("8.8.8.8")

    assert result["status"] == "success"
    assert result["abuse_confidence_score"] == 75
    assert result["total_reports"] == 20
    mock_get.assert_called_once()


@patch("scripts.threat_intel.requests.get")
def test_api_timeout_is_handled(mock_get, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake_test_key")

    import requests

    mock_get.side_effect = requests.Timeout()

    result = check_ip_reputation("8.8.8.8")

    assert result["status"] == "error"


@patch("scripts.threat_intel.requests.get")
def test_invalid_api_response_is_handled(mock_get, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake_test_key")

    mock_response = Mock()
    mock_response.json.return_value = {"unexpected": "response"}

    mock_get.return_value = mock_response

    result = check_ip_reputation("8.8.8.8")

    assert result["status"] == "error"


@patch("scripts.threat_intel.requests.get")
def test_reputation_results_are_cached(mock_get, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fake_test_key")

    mock_response = Mock()
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 10,
            "totalReports": 2,
            "lastReportedAt": None,
        }
    }

    mock_get.return_value = mock_response

    first = check_ip_reputation("8.8.8.8")
    second = check_ip_reputation("8.8.8.8")

    assert first == second
    mock_get.assert_called_once()
