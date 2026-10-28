
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / "data" / "cybersecurity_intrusion_data.csv"
OUTPUT_FILE = ROOT / "reports" / "ml_alerts.json"

TARGET = "attack_detected"
THRESHOLD = 0.40
RANDOM_STATE = 42


def build_model(X):
    numeric_cols = X.select_dtypes(include="number").columns.tolist()
    categorical_cols = X.select_dtypes(exclude="number").columns.tolist()

    preprocessor = ColumnTransformer([
        ("numeric", SimpleImputer(strategy="median"), numeric_cols),
        ("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical_cols),
    ])

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=2,
        )),
    ])


def severity_for(probability):
    if probability >= 0.70:
        return "high"
    if probability >= 0.50:
        return "medium"
    return "low"


def main():
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

    df = pd.read_csv(DATA_FILE).dropna(subset=[TARGET])

    y = df[TARGET].astype(int)
    X = df.drop(columns=[TARGET, "session_id"], errors="ignore")

    # Preserve a held-out test set for predictions and evaluation.
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    model = build_model(X_train)
    model.fit(X_train, y_train)

    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= THRESHOLD).astype(int)

    alerts = []
    for row_index, prediction, probability in zip(
        X_test.index, predictions, probabilities
    ):
        if prediction != 1:
            continue

        probability = float(probability)

        alerts.append({
            "session_id": str(df.loc[row_index, "session_id"]),
            "alert_type": "session_intrusion_detection",
            "predicted_label": "attack",
            "attack_probability": round(probability, 4),
            "threshold": THRESHOLD,
            "severity": severity_for(probability),
        })

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": "RandomForestClassifier",
        "dataset": DATA_FILE.name,
        "evaluation_scope": "held-out test split",
        "test_records": int(len(X_test)),
        "threshold": THRESHOLD,
        "alert_count": len(alerts),
        "alerts": alerts,
        "limitations": [
            "Alerts are predictions on a held-out public dataset.",
            "The dataset label-generation process is unverified.",
            "Confidence is a model probability, not proof of an attack.",
            "The dataset has no source IP or event timestamp fields.",
        ],
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, indent=2) + "\n")

    print(f"Test records processed: {len(X_test)}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Threshold: {THRESHOLD}")
    print(f"Alert report saved to: {OUTPUT_FILE}")

    if alerts:
        print("\nFirst three alerts:")
        print(json.dumps(alerts[:3], indent=2))


if __name__ == "__main__":
    main()
