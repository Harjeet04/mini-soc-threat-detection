
import ipaddress


def classify_ip(value):
    """Classify an IP address without making external requests."""

    if not value:
        return {
            "classification": "unknown",
            "globally_routable": False,
            "reason": "No source IP available",
        }

    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return {
            "classification": "invalid",
            "globally_routable": False,
            "reason": "Invalid IP address",
        }

    documentation_ranges = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    if any(ip in network for network in documentation_ranges):
        category = "documentation"
        reason = "Reserved documentation IP range"

    elif ip.is_loopback:
        category = "loopback"
        reason = "Loopback address"

    elif ip.is_private:
        category = "private"
        reason = "Private or special-use address"

    elif ip.is_link_local:
        category = "link_local"
        reason = "Link-local address"

    elif ip.is_multicast:
        category = "multicast"
        reason = "Multicast address"

    elif ip.is_reserved:
        category = "reserved"
        reason = "Reserved IP address"

    elif ip.is_global:
        category = "public"
        reason = "Globally routable IP address"

    else:
        category = "non_global"
        reason = "Not globally routable"

    return {
        "classification": category,
        "globally_routable": ip.is_global,
        "reason": reason,
    }


def enrich_alert(alert):
    """Add IP context to an existing security alert."""

    enriched = alert.copy()

    ip_context = classify_ip(alert.get("source_ip"))

    enriched["ip_context"] = ip_context

    # These require external data sources.
    enriched["geolocation"] = "not_checked"
    enriched["external_reputation"] = "not_checked"

    return enriched


def enrich_alerts(alerts):
    """Enrich a list of security alerts."""

    return [enrich_alert(alert) for alert in alerts]
