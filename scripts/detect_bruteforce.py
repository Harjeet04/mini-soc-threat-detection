import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path("data/sample_auth.jsonl")
OUTPUT_FILE = Path("reports/alerts.json")

THRESHOLD = 5
WINDOW = timedelta(minutes=5)


def main():
    failures = defaultdict(list)

    with LOG_FILE.open(encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            try:
                event = json.loads(line)
                if event.get("event_type") != "authentication_failure":
                    continue

                source_ip = event.get("source_ip")
                timestamp = datetime.fromisoformat(event["timestamp"])

                if source_ip:
                    failures[source_ip].append(timestamp)

            except (json.JSONDecodeError, KeyError, ValueError) as error:
                print(f"Skipping invalid line {line_number}: {error}")

    alerts = []

    for source_ip, timestamps in failures.items():
        timestamps.sort()
        window = deque()

        for timestamp in timestamps:
            window.append(timestamp)

            while window and timestamp - window[0] > WINDOW:
                window.popleft()

            if len(window) >= THRESHOLD:
                alerts.append({
                    "rule": "Repeated Authentication Failures",
                    "severity": "high",
                    "source_ip": source_ip,
                    "failure_count": len(window),
                    "window_minutes": 5,
                    "first_seen": window[0].isoformat(),
                    "last_seen": timestamp.isoformat(),
                    "reason": (
                        f"{len(window)} failed logins within five minutes"
                    ),
                    "status": "requires_investigation",
                })
                break

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(alerts, indent=2),
        encoding="utf-8",
    )

    print(f"Alerts generated: {len(alerts)}")
    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
