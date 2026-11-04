
from datetime import datetime, timedelta, timezone

from scripts.detect_windows_bruteforce import detect_password_spraying


def make_events(accounts):
    now = datetime.now(timezone.utc)

    return {
        ("ip", "203.0.113.10"): [
            {
                "timestamp": now + timedelta(minutes=i),
                "source_ip": "203.0.113.10",
                "target_user": account,
                "computer": "TEST-WORKSTATION",
                "logon_type": 3,
            }
            for i, account in enumerate(accounts)
        ]
    }


def test_password_spraying_detected():
    failures = make_events(
        ["user1", "user2", "user3", "user4", "user5"]
    )

    alerts = detect_password_spraying(failures)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "windows_password_spraying"
    assert alerts[0]["unique_accounts"] == 5


def test_same_account_is_not_password_spraying():
    failures = make_events(["user1"] * 5)

    alerts = detect_password_spraying(failures)

    assert alerts == []


def test_four_accounts_do_not_trigger_alert():
    failures = make_events(["user1", "user2", "user3", "user4"])

    alerts = detect_password_spraying(failures)

    assert alerts == []


def test_events_outside_window_do_not_trigger_alert():
    now = datetime.now(timezone.utc)

    failures = {
        ("ip", "203.0.113.10"): [
            {
                "timestamp": now + timedelta(minutes=i * 11),
                "source_ip": "203.0.113.10",
                "target_user": f"user{i}",
                "computer": "TEST-WORKSTATION",
                "logon_type": 3,
            }
            for i in range(5)
        ]
    }

    alerts = detect_password_spraying(failures)

    assert alerts == []
