
import hashlib
import json
import os

from datetime import datetime, timezone
from pathlib import Path


INVESTIGATION_FILE = Path("reports/investigations.json")

VALID_STATUSES = {
    "Open",
    "Investigating",
    "Resolved",
}


def get_alert_id(alert):
    """Generate a stable ID for an alert."""

    identity = "|".join(
        str(alert.get(field) or "")
        for field in (
            "rule",
            "source_ip",
            "target_user",
            "computer",
            "logon_type",
            "first_seen",
            "last_seen",
        )
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:16]


def load_investigations(path=INVESTIGATION_FILE):
    """Load locally saved investigation records."""

    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))

        if isinstance(data, dict):
            return data

    except (json.JSONDecodeError, OSError):
        pass

    return {}


def save_investigations(records, path=INVESTIGATION_FILE):
    """Save records safely using an atomic file replacement."""

    path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = path.with_suffix(path.suffix + ".tmp")

    try:
        temporary_path.write_text(
            json.dumps(records, indent=2),
            encoding="utf-8",
        )

        os.replace(temporary_path, path)

    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def update_investigation(alert, status, notes, path=INVESTIGATION_FILE):
    """Create or update an investigation for an alert."""

    if status not in VALID_STATUSES:
        raise ValueError("Invalid investigation status")

    records = load_investigations(path)
    alert_id = get_alert_id(alert)

    now = datetime.now(timezone.utc).isoformat()

    record = records.get(alert_id, {})

    record.update({
        "alert_id": alert_id,
        "alert": alert,
        "status": status,
        "notes": notes.strip(),
        "updated_at": now,
    })

    if "created_at" not in record:
        record["created_at"] = now

    records[alert_id] = record

    save_investigations(records, path)

    return record



def find_related_events(alert, events):
    """Find authentication events related to a Windows alert."""

    if events.empty:
        return events.copy()

    related = events.copy()

    source_ip = alert.get("source_ip")
    target_user = alert.get("target_user")
    computer = alert.get("computer")
    logon_type = alert.get("logon_type")

    if source_ip:
        if "source_ip" not in related.columns:
            return related.iloc[0:0]

        related = related[
            related["source_ip"].astype(str) == str(source_ip)
        ]
    elif target_user and computer:
        if not {"target_user", "computer"}.issubset(related.columns):
            return related.iloc[0:0]

        related = related[
            (related["target_user"].astype(str) == str(target_user))
            & (related["computer"].astype(str) == str(computer))
        ]
    else:
        return related.iloc[0:0]

    if logon_type is not None and "logon_type" in related.columns:
        related = related[
            related["logon_type"].astype(str) == str(logon_type)
        ]

    alert_type = alert.get("alert_type")

    if "event_type" in related.columns:
        if alert_type == "failed_login_followed_by_success":
            related = related[
                related["event_type"].isin([
                    "authentication_failure",
                    "authentication_success",
                ])
            ]
        else:
            related = related[
                related["event_type"] == "authentication_failure"
            ]

    if "timestamp" in related.columns:
        timestamps = __import__("pandas").to_datetime(
            related["timestamp"], utc=True, errors="coerce"
        )

        start_time = alert.get("failure_time") or alert.get("first_seen")
        end_time = alert.get("success_time") or alert.get("last_seen")

        if start_time and end_time:
            pd = __import__("pandas")
            start = pd.to_datetime(start_time, utc=True, errors="coerce")
            end = pd.to_datetime(end_time, utc=True, errors="coerce")

            if not pd.isna(start) and not pd.isna(end):
                related = related[
                    timestamps.between(start, end)
                ]

    return related
