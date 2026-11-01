
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detect_windows_bruteforce import (
    load_failures,
    detect_bruteforce,

)


EVENT_FILE = Path("data/demo_auth_events.jsonl")
ALERT_FILE = Path("reports/demo_windows_alerts.json")

DEMO_IP = "192.0.2.50"
DEMO_USER = "demo_user"
DEMO_COMPUTER = "DEMO-WORKSTATION"
DEMO_LOGON_TYPE = "2"

ATTEMPTS = 5
INTERVAL_SECONDS = 30


def generate_events():
    """Generate synthetic failed Windows authentication events."""

    now = datetime.now(timezone.utc)

    events = []

    for attempt in range(ATTEMPTS):
        timestamp = now - timedelta(
            seconds=INTERVAL_SECONDS * (ATTEMPTS - attempt - 1)
        )

        event = {
            "timestamp": timestamp.isoformat(),
            "event_id": 4625,
            "event_type": "authentication_failure",
            "source_ip": DEMO_IP,
            "target_user": DEMO_USER,
            "computer": DEMO_COMPUTER,
            "logon_type": DEMO_LOGON_TYPE,
            "status": "0xC000006D",
            "sub_status": "0xC000006A",
            "data_source": "synthetic_demo",
        }

        events.append(event)

    return events


def main():
    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    events = generate_events()

    # Save the synthetic events separately.
    with EVENT_FILE.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    # Reuse the existing Windows brute-force detector.
    failures, invalid_count = load_failures(EVENT_FILE)
    alerts = detect_bruteforce(failures)

    # Clearly identify generated alerts as simulations.
    for alert in alerts:
        alert["data_source"] = "synthetic_demo"
        alert["simulation"] = True

    with ALERT_FILE.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)

    print("Synthetic brute-force simulation completed.")
    print(f"Events generated: {len(events)}")
    print(f"Invalid events skipped: {invalid_count}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Event file: {EVENT_FILE}")
    print(f"Alert file: {ALERT_FILE}")

    if alerts:
        print("\nGenerated alert:")
        print(json.dumps(alerts[0], indent=2))
    else:
        print("\nNo alert generated. Check the detection threshold.")


if __name__ == "__main__":
    main()
