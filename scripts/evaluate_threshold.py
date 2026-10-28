
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


DATA_FILE = "data/cybersecurity_intrusion_data.csv"
THRESHOLDS = [0.40, 0.50]


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
            random_state=42,
            n_jobs=2,
        )),
    ])


def main():
    df = pd.read_csv(DATA_FILE).dropna(subset=["attack_detected"])

    y = df["attack_detected"].astype(int)
    X = df.drop(columns=["attack_detected", "session_id"], errors="ignore")

    # First reserve the final test set.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    # Split the remaining training data into fit and validation sets.
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train,
        test_size=0.25,
        random_state=24,
        stratify=y_train,
    )

    # Fit using only the fit split.
    model = build_model(X_fit)
    model.fit(X_fit, y_fit)

    # Select the threshold using validation data only.
    val_probabilities = model.predict_proba(X_val)[:, 1]

    print("Validation results")
    print("Threshold | Precision | Recall | F1-score")

    for threshold in THRESHOLDS:
        val_predictions = (val_probabilities >= threshold).astype(int)

        print(
            f"{threshold:9.2f} | "
            f"{precision_score(y_val, val_predictions, zero_division=0):9.3f} | "
            f"{recall_score(y_val, val_predictions, zero_division=0):6.3f} | "
            f"{f1_score(y_val, val_predictions, zero_division=0):.3f}"
        )

    # After selecting a threshold, refit on all training data.
    selected_threshold = 0.40
    final_model = build_model(X_train)
    final_model.fit(X_train, y_train)

    # Evaluate the selected threshold once on the held-out test set.
    test_probabilities = final_model.predict_proba(X_test)[:, 1]
    test_predictions = (test_probabilities >= selected_threshold).astype(int)

    print(f"\nHeld-out test results at threshold {selected_threshold:.2f}")
    print(f"Accuracy: {accuracy_score(y_test, test_predictions):.3f}")
    print(classification_report(
        y_test, test_predictions, zero_division=0
    ))
    print("Confusion matrix (rows=true, columns=predicted):")
    print(confusion_matrix(y_test, test_predictions, labels=[0, 1]))


if __name__ == "__main__":
    main()
