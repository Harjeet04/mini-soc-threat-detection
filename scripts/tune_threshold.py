
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


DATA_FILE = "data/cybersecurity_intrusion_data.csv"
THRESHOLDS = [0.30, 0.40, 0.50, 0.60, 0.70]


def build_model(X):
    numeric = X.select_dtypes(include="number").columns.tolist()
    categorical = X.select_dtypes(exclude="number").columns.tolist()

    preprocess = ColumnTransformer([
        ("num", SimpleImputer(strategy="median"), numeric),
        ("cat", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical),
    ])

    return Pipeline([
        ("preprocess", preprocess),
        ("model", RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            n_jobs=2,
        )),
    ])


def main():
    df = pd.read_csv(DATA_FILE).dropna(subset=["attack_detected"])
    y = df["attack_detected"].astype(int)
    X = df.drop(columns=["attack_detected", "session_id"], errors="ignore")

    # Hold out a test set; use the validation split only to compare thresholds.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.25, random_state=24, stratify=y_train
    )

    model = build_model(X_fit)
    model.fit(X_fit, y_fit)
    probabilities = model.predict_proba(X_val)[:, 1]

    print("Validation results (do not treat these as final test results)")
    print("threshold | precision | recall | f1 | false positives | false negatives")

    for threshold in THRESHOLDS:
        predictions = (probabilities >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(
            y_val, predictions, labels=[0, 1]
        ).ravel()

        print(
            f"{threshold:9.2f} | "
            f"{precision_score(y_val, predictions, zero_division=0):9.3f} | "
            f"{recall_score(y_val, predictions, zero_division=0):6.3f} | "
            f"{f1_score(y_val, predictions, zero_division=0):.3f} | "
            f"{fp:14d} | {fn:14d}"
        )

    print("\nChoose a threshold based on the trade-off between missed attacks")
    print("and false alerts. Do not choose using the final test set.")


if __name__ == "__main__":
    main()
