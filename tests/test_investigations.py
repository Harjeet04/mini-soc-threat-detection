
import json

import pandas as pd
import pytest

from scripts.investigations import (
    get_alert_id,
    load_investigations,
    update_investigation,
    find_related_events,
)


@pytest.fixture
def sample_alert():
    return {
        "rule": "Repeated Authentication Failures",
        "severity": "high",
        "source_ip": "192.0.2.10",
        "target_user": "testuser",
        "computer": "TEST-PC",
        "logon_type": "2",
        "failure_count": 5,
        "first_seen": "2026-10-30T10:00:00+00:00",
        "last_seen": "2026-10-30T10:04:00+00:00",
    }


def test_alert_id_is_stable(sample_alert):
    assert get_alert_id(sample_alert) == get_alert_id(sample_alert)


def test_alert_id_changes_for_different_alert(sample_alert):
    other = sample_alert.copy()
    other["source_ip"] = "192.0.2.20"

    assert get_alert_id(sample_alert) != get_alert_id(other)


def test_new_investigation_is_saved(tmp_path, sample_alert):
    path = tmp_path / "investigations.json"

    record = update_investigation(
        sample_alert,
        "Open",
        "Initial review required.",
        path,
    )

    assert record["status"] == "Open"
    assert record["notes"] == "Initial review required."
    assert path.exists()


def test_investigation_can_be_updated(tmp_path, sample_alert):
    path = tmp_path / "investigations.json"

    first = update_investigation(
        sample_alert, "Open", "New alert.", path
    )

    second = update_investigation(
        sample_alert, "Investigating", "Reviewing events.", path
    )

    assert second["status"] == "Investigating"
    assert second["created_at"] == first["created_at"]
    assert second["notes"] == "Reviewing events."


def test_investigation_persists_after_reload(tmp_path, sample_alert):
    path = tmp_path / "investigations.json"

    update_investigation(
        sample_alert, "Resolved", "Reviewed and closed.", path
    )

    records = load_investigations(path)
    alert_id = get_alert_id(sample_alert)

    assert records[alert_id]["status"] == "Resolved"


def test_invalid_status_is_rejected(tmp_path, sample_alert):
    path = tmp_path / "investigations.json"

    with pytest.raises(ValueError):
        update_investigation(
            sample_alert, "Closed", "Invalid status.", path
        )


def test_related_events_match_source_ip_and_time(sample_alert):
    events = pd.DataFrame([
        {
            "timestamp": "2026-10-30T10:01:00Z",
            "source_ip": "192.0.2.10",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "2",
            "event_type": "authentication_failure",
        },
        {
            "timestamp": "2026-10-30T10:02:00Z",
            "source_ip": "192.0.2.20",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "2",
            "event_type": "authentication_failure",
        },
        {
            "timestamp": "2026-10-30T10:10:00Z",
            "source_ip": "192.0.2.10",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "2",
            "event_type": "authentication_failure",
        },
    ])

    result = find_related_events(sample_alert, events)

    assert len(result) == 1
    assert result.iloc[0]["source_ip"] == "192.0.2.10"


def test_empty_events_return_empty_result(sample_alert):
    result = find_related_events(
        sample_alert,
        pd.DataFrame(),
    )

    assert result.empty


def test_unrelated_source_ip_is_excluded(sample_alert):
    events = pd.DataFrame([
        {
            "timestamp": "2026-10-30T10:01:00Z",
            "source_ip": "192.0.2.99",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "2",
            "event_type": "authentication_failure",
        }
    ])

    result = find_related_events(sample_alert, events)

    assert result.empty


def test_successful_logons_are_excluded(sample_alert):
    events = pd.DataFrame([
        {
            "timestamp": "2026-10-30T10:01:00Z",
            "source_ip": "192.0.2.10",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "2",
            "event_type": "authentication_success",
        }
    ])

    result = find_related_events(sample_alert, events)

    assert result.empty


def test_wrong_logon_type_is_excluded(sample_alert):
    events = pd.DataFrame([
        {
            "timestamp": "2026-10-30T10:01:00Z",
            "source_ip": "192.0.2.10",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "3",
            "event_type": "authentication_failure",
        }
    ])

    result = find_related_events(sample_alert, events)

    assert result.empty


def test_account_and_computer_matching_without_source_ip(sample_alert):
    alert = sample_alert.copy()
    alert.pop("source_ip")

    events = pd.DataFrame([
        {
            "timestamp": "2026-10-30T10:01:00Z",
            "source_ip": "192.0.2.10",
            "target_user": "testuser",
            "computer": "TEST-PC",
            "logon_type": "2",
            "event_type": "authentication_failure",
        }
    ])

    result = find_related_events(alert, events)

    assert len(result) == 1
    assert result.iloc[0]["target_user"] == "testuser"
