
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from scripts.detect_bruteforce import (
    detect_bruteforce,
    load_failures,
)


class BruteForceDetectionTests(unittest.TestCase):

    def make_failures(self, count, interval_seconds=10):
        start = datetime(2026, 10, 24, 9, 0, 0)
        return {
            "192.0.2.10": [
                start + timedelta(seconds=i * interval_seconds)
                for i in range(count)
            ]
        }

    def test_five_failures_trigger_alert(self):
        alerts = detect_bruteforce(self.make_failures(5))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 5)

    def test_four_failures_do_not_trigger_alert(self):
        alerts = detect_bruteforce(self.make_failures(4))
        self.assertEqual(alerts, [])

    def test_failures_outside_window_do_not_trigger(self):
        # Five attempts spanning more than five minutes.
        failures = self.make_failures(5, interval_seconds=90)
        alerts = detect_bruteforce(failures)
        self.assertEqual(alerts, [])

    def test_each_source_ip_is_checked_separately(self):
        failures = self.make_failures(5)
        failures["192.0.2.20"] = self.make_failures(4)["192.0.2.10"]

        alerts = detect_bruteforce(failures)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.0.2.10")

    def test_malformed_json_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "events.jsonl"
            log_file.write_text(
                '{invalid json}\n'
                '{"timestamp":"2026-10-24T09:00:00",'
                '"event_type":"authentication_failure",'
                '"source_ip":"192.0.2.10"}\n',
                encoding="utf-8",
            )

            failures, invalid_count = load_failures(log_file)

            self.assertEqual(invalid_count, 1)
            self.assertEqual(len(failures["192.0.2.10"]), 1)

    def test_successful_logins_are_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "events.jsonl"
            event = {
                "timestamp": "2026-10-24T09:00:00",
                "event_type": "authentication_success",
                "source_ip": "192.0.2.10",
            }
            log_file.write_text(json.dumps(event) + "\n", encoding="utf-8")

            failures, invalid_count = load_failures(log_file)

            self.assertEqual(dict(failures), {})
            self.assertEqual(invalid_count, 0)


if __name__ == "__main__":
    unittest.main()
