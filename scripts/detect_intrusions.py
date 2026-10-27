
import json
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


ROOT = Path(__file__).resolve().parents[1]
DATA_FILE = ROOT / "data" / "cybersecurity_intrusion_data.csv"
REPORT_FILE = ROOT / "reports" / "intrusion_model_report.json"

TARGET = "attack_detected"
DROP_COLUMNS = ["session_id", TARGET]


def main():
    if not DATA_FILE.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

    df = pd.read_csv(DATA_FILE)

    if TARGET not in df.columns:
        raise ValueError(f"Missing target column: {TARGET}")

    df = df.dropna(subset=[TARGET])
    y = df[TARGET].astype(int)
    X = df.drop(columns=DROP_COLUMNS, errors="ignore")

    # Detect numeric and categorical columns automatically.
    numeric_cols = X.select_dtypes(include="number").columns.tolist()
    categorical_cols = X.select_dtypes(
        exclude="number"
    ).columns.tolist()

    numeric_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
    ])

    categorical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="ignore")),
    ])

    preprocessor = ColumnTransformer([
        ("numeric", numeric_pipeline, numeric_cols),
        ("categorical", categorical_pipeline, categorical_cols),
    ])

    model = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            n_jobs=2,
        )),
    ])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    labels = sorted(y.unique().tolist())
    matrix = confusion_matrix(y_test, predictions, labels=labels)

    report = {
        "dataset": DATA_FILE.name,
        "total_records": int(len(df)),
        "training_records": int(len(X_train)),
        "test_records": int(len(X_test)),
        "features": X.columns.tolist(),
        "target": TARGET,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": matrix.tolist(),
        "confusion_matrix_labels": labels,
        "note": (
            "Evaluation on this dataset only. High scores may reflect "
            "how the dataset's attack labels were generated."
        ),
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(json.dumps(report, indent=2))

    print(f"Dataset records: {len(df)}")
    print(f"Training records: {len(X_train)}")
    print(f"Test records: {len(X_test)}")
    print(f"Accuracy: {report['accuracy']:.3f}")
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, labels=labels, zero_division=0
    ))
    print("Confusion matrix (rows=true, columns=predicted):")
    print(matrix)
    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
