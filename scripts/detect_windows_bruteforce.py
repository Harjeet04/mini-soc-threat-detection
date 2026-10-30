
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


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    failures, invalid_count = load_failures(INPUT_FILE)
    alerts = detect_bruteforce(failures)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(alerts, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"Invalid or unattributed events skipped: {invalid_count}")
    print(f"Groups examined: {len(failures)}")
    print(f"Windows alerts generated: {len(alerts)}")
    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
