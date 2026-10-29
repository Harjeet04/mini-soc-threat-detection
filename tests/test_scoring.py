
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "score_sessions.py"
DATA_FILE = ROOT / "data" / "cybersecurity_intrusion_data.csv"
SAMPLE_FILE = ROOT / "data" / "sample_sessions.csv"
OUTPUT_FILE = ROOT / "reports" / "test_scored_sessions.json"


def run_scorer(input_file, output_file):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_saved_model_scores_sample_records():
    result = run_scorer(SAMPLE_FILE, OUTPUT_FILE)

    assert result.returncode == 0, result.stderr
    report = json.loads(OUTPUT_FILE.read_text())

    assert report["records_scored"] == 20
    assert report["alert_count"] == sum(
        row["predicted_label"] == "attack"
        for row in report["results"]
    )

    for row in report["results"]:
        assert row["predicted_label"] in {"attack", "normal"}
        assert 0.0 <= row["attack_probability"] <= 1.0


def test_missing_required_feature_is_rejected(tmp_path):
    df = pd.read_csv(DATA_FILE, nrows=3)
    df = df.drop(columns=["failed_logins"])
    bad_file = tmp_path / "missing_feature.csv"
    df.to_csv(bad_file, index=False)

    result = run_scorer(bad_file, tmp_path / "output.json")

    assert result.returncode != 0
    assert "missing required features" in result.stderr.lower()
