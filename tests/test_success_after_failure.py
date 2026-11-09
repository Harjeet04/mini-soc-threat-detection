
from scripts.detect_success_after_failure import (
    detect_success_after_failure,
)


def make_event(event_type, timestamp, user="HARDEEP",
               computer="TEST-PC"):
    return {
        "event_type": event_type,
        "timestamp": timestamp,
        "target_user": user,
        "computer": computer,
        "source_ip": None,
    }


def test_failed_login_followed_by_success():
    events = [
        make_event("authentication_failure", "2026-11-01T10:00:00+00:00"),
        make_event("authentication_success", "2026-11-01T10:01:00+00:00"),
    ]

    alerts = detect_success_after_failure(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "failed_login_followed_by_success"
    assert alerts[0]["target_user"] == "HARDEEP"


def test_success_before_failure_does_not_trigger():
    events = [
        make_event("authentication_success", "2026-11-01T10:00:00+00:00"),
        make_event("authentication_failure", "2026-11-01T10:01:00+00:00"),
    ]

    assert detect_success_after_failure(events) == []


def test_success_after_five_minutes_does_not_trigger():
    events = [
        make_event("authentication_failure", "2026-11-01T10:00:00+00:00"),
        make_event("authentication_success", "2026-11-01T10:06:00+00:00"),
    ]

    assert detect_success_after_failure(events) == []


def test_different_accounts_do_not_match():
    events = [
        make_event("authentication_failure", "2026-11-01T10:00:00+00:00"),
        make_event(
            "authentication_success",
            "2026-11-01T10:01:00+00:00",
            user="OTHER_USER",
        ),
    ]

    assert detect_success_after_failure(events) == []


def test_different_computers_do_not_match():
    events = [
        make_event("authentication_failure", "2026-11-01T10:00:00+00:00"),
        make_event(
            "authentication_success",
            "2026-11-01T10:01:00+00:00",
            computer="OTHER-PC",
        ),
    ]

    assert detect_success_after_failure(events) == []


def test_missing_timestamp_is_ignored():
    events = [
        make_event("authentication_failure", None),
        make_event("authentication_success", "2026-11-01T10:01:00+00:00"),
    ]

    assert detect_success_after_failure(events) == []


def test_success_exactly_five_minutes_later_triggers():
    events = [
        make_event("authentication_failure", "2026-11-01T10:00:00+00:00"),
        make_event("authentication_success", "2026-11-01T10:05:00+00:00"),
    ]

    assert len(detect_success_after_failure(events)) == 1
