
from datetime import datetime, timedelta


WINDOW = timedelta(minutes=5)


def parse_timestamp(value):
    """Convert an ISO timestamp into a timezone-aware datetime."""
    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            return timestamp.replace(
                tzinfo=__import__("datetime").timezone.utc
            )

        return timestamp

    except (ValueError, TypeError):
        return None


def detect_success_after_failure(events):
    """
    Detect a successful login within five minutes
    after a failed login for the same account and computer.
    """
    grouped_events = {}

    for event in events:
        event_type = event.get("event_type")
        username = event.get("target_user")
        computer = event.get("computer")
        timestamp = parse_timestamp(event.get("timestamp"))

        if event_type not in (
            "authentication_failure",
            "authentication_success",
        ):
            continue

        if not username or not computer or not timestamp:
            continue

        key = (str(username).casefold(), str(computer).casefold())

        grouped_events.setdefault(key, []).append({
            **event,
            "_parsed_timestamp": timestamp,
        })

    alerts = []

    for (username, computer), account_events in grouped_events.items():
        account_events.sort(
            key=lambda event: event["_parsed_timestamp"]
        )

        failures = [
            event for event in account_events
            if event["event_type"] == "authentication_failure"
        ]

        successes = [
            event for event in account_events
            if event["event_type"] == "authentication_success"
        ]

        for failure in failures:
            failure_time = failure["_parsed_timestamp"]

            matching_success = next(
                (
                    success for success in successes
                    if failure_time < success["_parsed_timestamp"]
                    <= failure_time + WINDOW
                ),
                None,
            )

            if matching_success:
                alerts.append({
                    "alert_type": "failed_login_followed_by_success",
                    "severity": "high",
                    "status": "requires_investigation",
                    "target_user": failure["target_user"],
                    "computer": failure["computer"],
                    "source_ip": failure.get("source_ip"),
                    "failure_time": failure["timestamp"],
                    "success_time": matching_success["timestamp"],
                    "window_minutes": 5,
                    "reason": (
                        "A successful login occurred within five "
                        "minutes after a failed login."
                    ),
                })

                break

    return alerts
