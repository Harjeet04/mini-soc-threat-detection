
import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / "data" / "cybersecurity_intrusion_data.csv"
MODEL_FILE = ROOT / "models" / "intrusion_model.joblib"
METADATA_FILE = ROOT / "models" / "model_metadata.json"

TARGET = "attack_detected"
DROP_COLUMNS = ["session_id", TARGET]
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


def main():
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

    df = pd.read_csv(DATA_FILE).dropna(subset=[TARGET])
    y = df[TARGET].astype(int)
    X = df.drop(columns=DROP_COLUMNS, errors="ignore")

    if y.nunique() != 2:
        raise ValueError("Expected two target classes: normal and attack")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # Train on the training split for this initial saved-model version.
    model = build_model(X_train)
    model.fit(X_train, y_train)

    MODEL_FILE.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)

    metadata = {
        "model_type": "RandomForestClassifier",
        "dataset": DATA_FILE.name,
        "target": TARGET,
        "features": X.columns.tolist(),
        "threshold": THRESHOLD,
        "random_state": RANDOM_STATE,
        "training_records": len(X_train),
        "held_out_records": len(X_test),
        "note": (
            "Initial saved model. Evaluation uses a held-out split. "
            "Dataset label-generation process is unverified."
        ),
    }

    METADATA_FILE.write_text(json.dumps(metadata, indent=2) + "\n")

    print(f"Model saved: {MODEL_FILE}")
    print(f"Metadata saved: {METADATA_FILE}")
    print(f"Training records: {len(X_train)}")
    print(f"Held-out records: {len(X_test)}")
    print(f"Features: {len(X.columns)}")
    print(f"Threshold: {THRESHOLD}")


if __name__ == "__main__":
    main()
