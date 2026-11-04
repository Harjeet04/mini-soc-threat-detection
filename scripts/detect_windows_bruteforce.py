
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path


INPUT_FILE = Path("data/normalized_auth.jsonl")
OUTPUT_FILE = Path("reports/windows_alerts.json")

THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def load_failures(log_file):
    failures = defaultdict(list)
    invalid_count = 0

    with log_file.open(encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)

                if not isinstance(event, dict):
                    raise ValueError("Event must be a JSON object")

                if event.get("event_type") != "authentication_failure":
                    continue

                timestamp = datetime.fromisoformat(event["timestamp"])

                source_ip = event.get("source_ip")
                target_user = event.get("target_user")
                computer = event.get("computer")
                logon_type = event.get("logon_type")

                if isinstance(source_ip, str):
                    source_ip = source_ip.strip()

                if not source_ip:
                    # Do not group unattributed events together.
                    if not target_user or not computer:
                        invalid_count += 1
                        continue

                    key = (
                        "account",
                        target_user,
                        computer,
                        str(logon_type or "unknown"),
                    )
                else:
                    key = ("ip", source_ip)

                failures[key].append({
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "target_user": target_user,
                    "computer": computer,
                    "logon_type": logon_type,
                })

            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                invalid_count += 1

    return failures, invalid_count


def detect_bruteforce(failures):
    alerts = []

    for key, events in failures.items():
        events.sort(key=lambda event: event["timestamp"])
        window = deque()

        for event in events:
            timestamp = event["timestamp"]
            window.append(event)

            while window and timestamp - window[0]["timestamp"] > WINDOW:
                window.popleft()

            if len(window) >= THRESHOLD:
                first = window[0]

                if key[0] == "ip":
                    attribution = "source_ip"
                    source_ip = key[1]
                else:
                    attribution = "account_context"
                    source_ip = None

                alerts.append({
                    "alert_type": "windows_repeated_authentication_failures",
                    "severity": "high",
                    "status": "requires_investigation",
                    "attribution": attribution,
                    "source_ip": source_ip,
                    "target_user": first["target_user"],
                    "computer": first["computer"],
                    "logon_type": first["logon_type"],
                    "failure_count": len(window),
                    "window_minutes": 5,
                    "first_seen": first["timestamp"].isoformat(),
                    "last_seen": timestamp.isoformat(),
                    "reason": (
                        f"{len(window)} failed logons within five minutes"
                    ),
                })

                # One alert per grouping key per execution.
                break

    return alerts

def detect_password_spraying(failures):
    alerts = []
    events_by_ip = defaultdict(list)

    # Combine failed logons from all groups by source IP.
    for events in failures.values():
        for event in events:
            source_ip = event.get("source_ip")
            target_user = event.get("target_user")

            if source_ip and target_user:
                events_by_ip[source_ip].append(event)

    spray_threshold = 5
    spray_window = timedelta(minutes=10)

    for source_ip, events in events_by_ip.items():
        events.sort(key=lambda event: event["timestamp"])

        window = deque()
        user_counts = defaultdict(int)
        alert_created = False

        for event in events:
            timestamp = event["timestamp"]
            target_user = event["target_user"]

            window.append(event)
            user_counts[target_user] += 1

            # Remove events older than the 10-minute window.
            while (
                window
                and timestamp - window[0]["timestamp"] > spray_window
            ):
                old_event = window.popleft()
                old_user = old_event["target_user"]
                user_counts[old_user] -= 1

                if user_counts[old_user] == 0:
                    del user_counts[old_user]

            # Count distinct accounts, not total failed attempts.
            if len(user_counts) >= spray_threshold:
                alerts.append({
                    "alert_type": "windows_password_spraying",
                    "severity": "high",
                    "status": "requires_investigation",
                    "attribution": "source_ip",
                    "source_ip": source_ip,
                    "target_user": ", ".join(sorted(user_counts)),
                    "computer": event.get("computer"),
                    "logon_type": event.get("logon_type"),
                    "failure_count": len(window),
                    "unique_accounts": len(user_counts),
                    "window_minutes": 10,
                    "first_seen": window[0]["timestamp"].isoformat(),
                    "last_seen": timestamp.isoformat(),
                    "reason": (
                        f"{len(user_counts)} distinct accounts targeted "
                        "within ten minutes"
                    ),
                })

                alert_created = True
                break

    return alerts
def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    failures, invalid_count = load_failures(INPUT_FILE)

    # Run both detection rules.
    brute_force_alerts = detect_bruteforce(failures)
    password_spray_alerts = detect_password_spraying(failures)

    # Combine alerts into one report.
    alerts = brute_force_alerts + password_spray_alerts
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(alerts, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Invalid or unattributed events skipped: {invalid_count}")
    print(f"Groups examined: {len(failures)}")
    print(f"Brute-force alerts generated: {len(brute_force_alerts)}")
    print(f"Password-spraying alerts generated: {len(password_spray_alerts)}")
    print(f"Total alerts generated: {len(alerts)}")
    print(f"Report saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
