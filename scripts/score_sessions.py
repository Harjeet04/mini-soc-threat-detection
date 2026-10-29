
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
MODEL_FILE = ROOT / "models" / "intrusion_model.joblib"
METADATA_FILE = ROOT / "models" / "model_metadata.json"
DEFAULT_OUTPUT = ROOT / "reports" / "scored_sessions.json"

ID_COLUMN = "session_id"


def severity_for(probability):
    if probability >= 0.70:
        return "high"
    if probability >= 0.50:
        return "medium"
    return "low"


def main():
    parser = argparse.ArgumentParser(
        description="Score new session records using a saved Mini SOC model."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a CSV containing new session records.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Path for the JSON results.",
    )
    args = parser.parse_args()

    input_file = Path(args.input).expanduser()
    output_file = Path(args.output).expanduser()

    if not input_file.is_file():
        parser.error(f"Input file not found: {input_file}")

    if not MODEL_FILE.is_file() or not METADATA_FILE.is_file():
        parser.error("Saved model or metadata missing. Run train_model.py first.")

    metadata = json.loads(METADATA_FILE.read_text())
    required_features = metadata["features"]
    threshold = float(metadata["threshold"])

    df = pd.read_csv(input_file)

    missing = [column for column in required_features if column not in df.columns]
    if missing:
        parser.error(f"Input CSV is missing required features: {missing}")

    if df.empty:
        parser.error("Input CSV contains no records.")

    # Keep the session ID for the output, not as a model feature.
    if ID_COLUMN in df.columns:
        session_ids = df[ID_COLUMN].astype(str).tolist()
    else:
        session_ids = [f"row_{i + 1}" for i in range(len(df))]

    X = df[required_features].copy()

    model = joblib.load(MODEL_FILE)
    probabilities = model.predict_proba(X)[:, 1]

    results = []
    for session_id, probability in zip(session_ids, probabilities):
        probability = float(probability)
        predicted_attack = probability >= threshold

        results.append({
            "session_id": session_id,
            "predicted_label": "attack" if predicted_attack else "normal",
            "attack_probability": round(probability, 4),
            "threshold": threshold,
            "severity": (
                severity_for(probability) if predicted_attack else "none"
            ),
        })

    output = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": metadata["model_type"],
        "input_file": input_file.name,
        "records_scored": len(results),
        "threshold": threshold,
        "alert_count": sum(
            item["predicted_label"] == "attack" for item in results
        ),
        "results": results,
        "note": (
            "Predictions are model estimates, not proof of malicious activity. "
            "Use input data that follows the training dataset's feature schema."
        ),
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(output, indent=2) + "\n")

    print(f"Records scored: {len(results)}")
    print(f"Alerts generated: {output['alert_count']}")
    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
