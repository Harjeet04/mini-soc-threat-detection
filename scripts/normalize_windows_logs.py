
import json
from pathlib import Path

INPUT_FILE = Path("data/windows_auth_events.jsonl")
OUTPUT_FILE = Path("data/normalized_auth.jsonl")


def normalize_event(event):
    event_id = event.get("event_id")

    if event_id not in (4624, 4625):
        return None

    source_ip = event.get("source_ip")
    timestamp = event.get("timestamp")

    # Ignore missing, placeholder, or non-routable source addresses.
    if not source_ip or source_ip in ("-", "::1", "127.0.0.1"):
        source_ip = None

    return {
        "timestamp": timestamp,
        "event_type": (
            "authentication_failure"
            if event_id == 4625
            else "authentication_success"
        ),
        "source_ip": source_ip,
        "target_user": event.get("target_user"),
        "event_id": event_id,
        "computer": event.get("computer"),
        "logon_type": event.get("logon_type"),
        "status": event.get("status"),
        "sub_status": event.get("sub_status"),
    }

def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    count = 0
    skipped = 0

    with INPUT_FILE.open(encoding="utf-8-sig") as source, \
            OUTPUT_FILE.open("w", encoding="utf-8") as output:
        for line in source:
            if not line.strip():
                continue

            event = json.loads(line)
            normalized = normalize_event(event)

            if normalized is None:
                skipped += 1
                continue

            output.write(json.dumps(normalized) + "\n")
            count += 1

    print(f"Normalized events: {count}")
    print(f"Skipped events: {skipped}")
    print(f"Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
