import os
from functools import lru_cache

import requests

from scripts.enrich_alerts import classify_ip


API_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 10


def check_ip_reputation(ip_address):
    """
    Check a globally routable IP against AbuseIPDB.
    Never query private or reserved addresses.
    """

    ip_context = classify_ip(ip_address)

    if ip_context["classification"] != "public":
        return {
            "status": "skipped",
            "reason": ip_context["reason"],
            "abuse_confidence_score": None,
            "total_reports": None,
            "last_reported_at": None,
        }

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "status": "not_configured",
            "reason": "AbuseIPDB API key not configured",
            "abuse_confidence_score": None,
            "total_reports": None,
            "last_reported_at": None,
        }

    return _check_cached(ip_address, api_key)


@lru_cache(maxsize=256)
def _check_cached(ip_address, api_key):
    """Cache reputation results during the application session."""

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
    }

    try:
        response = requests.get(
            API_URL,
            headers=headers,
            params=params,
            timeout=TIMEOUT,
        )

        response.raise_for_status()
        data = response.json()["data"]

        return {
            "status": "success",
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
        }

    except requests.RequestException:
        return {
            "status": "error",
            "reason": "Unable to contact AbuseIPDB",
        }

    except (ValueError, KeyError, TypeError):
        return {
            "status": "error",
            "reason": "Invalid response from AbuseIPDB",
        }
