
import json
from datetime import datetime, timedelta, timezone

from scripts.detect_windows_bruteforce import (
    load_failures,
    detect_bruteforce,
)


def make_event(timestamp, event_id=4625, source_ip=None,
               target_user="testuser", computer="TEST-PC"):
    return {
        "timestamp": timestamp.isoformat(),
        "event_type": (
            "authentication_failure"
            if event_id == 4625
            else "authentication_success"
        ),
        "event_id": event_id,
        "source_ip": source_ip,
        "target_user": target_user,
        "computer": computer,
        "logon_type": "2",
    }


def write_events(path, events):
    with path.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")


def test_five_failures_from_same_ip_trigger_alert(tmp_path):
    start = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            start + timedelta(seconds=i * 30),
            source_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    log_file = tmp_path / "ip_events.jsonl"
    write_events(log_file, events)

    failures, invalid = load_failures(log_file)
    alerts = detect_bruteforce(failures)

    assert invalid == 0
    assert len(alerts) == 1
    assert alerts[0]["attribution"] == "source_ip"
    assert alerts[0]["source_ip"] == "192.0.2.10"


def test_five_local_failures_trigger_account_alert(tmp_path):
    start = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            start + timedelta(seconds=i * 30),
            source_ip=None,
        )
        for i in range(5)
    ]

    log_file = tmp_path / "local_events.jsonl"
    write_events(log_file, events)

    failures, invalid = load_failures(log_file)
    alerts = detect_bruteforce(failures)

    assert invalid == 0
    assert len(alerts) == 1
    assert alerts[0]["attribution"] == "account_context"
    assert alerts[0]["source_ip"] is None


def test_successful_logons_are_ignored(tmp_path):
    start = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            start + timedelta(seconds=i * 30),
            event_id=4624,
            source_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    log_file = tmp_path / "success_events.jsonl"
    write_events(log_file, events)

    failures, invalid = load_failures(log_file)

    assert invalid == 0
    assert len(detect_bruteforce(failures)) == 0


def test_unattributed_events_are_not_grouped(tmp_path):
    start = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            start + timedelta(seconds=i * 30),
            source_ip=None,
            target_user=None,
            computer=None,
        )
        for i in range(5)
    ]

    log_file = tmp_path / "unattributed_events.jsonl"
    write_events(log_file, events)

    failures, invalid = load_failures(log_file)

    assert invalid == 5
    assert len(detect_bruteforce(failures)) == 0


def test_failures_outside_five_minute_window_do_not_alert(tmp_path):
    start = datetime(2026, 10, 30, 10, 0, tzinfo=timezone.utc)

    events = [
        make_event(
            start + timedelta(minutes=i * 2),
            source_ip="192.0.2.10",
        )
        for i in range(5)
    ]

    log_file = tmp_path / "spread_events.jsonl"
    write_events(log_file, events)

    failures, invalid = load_failures(log_file)
    alerts = detect_bruteforce(failures)

    assert invalid == 0
    assert len(alerts) == 0
