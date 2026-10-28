
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

DATA_FILE = "data/cybersecurity_intrusion_data.csv"
TARGET = "attack_detected"
LOGIN_FEATURES = ["failed_logins", "login_attempts"]


def build_model(X):
    numeric = X.select_dtypes(include="number").columns.tolist()
    categorical = X.select_dtypes(exclude="number").columns.tolist()

    preprocessor = ColumnTransformer([
        ("num", SimpleImputer(strategy="median"), numeric),
        ("cat", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical),
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


def evaluate(name, X_train, X_test, y_train, y_test):
    model = build_model(X_train)
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    print(f"\n--- {name} ---")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.3f}")
    print(classification_report(
        y_test, predictions, zero_division=0
    ))


def main():
    df = pd.read_csv(DATA_FILE).dropna(subset=[TARGET])
    y = df[TARGET].astype(int)
    X = df.drop(columns=[TARGET, "session_id"], errors="ignore")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    evaluate(
        "All features",
        X_train, X_test, y_train, y_test
    )

    remaining = [c for c in X.columns if c not in LOGIN_FEATURES]
    evaluate(
        "Without login-attempt features",
        X_train[remaining], X_test[remaining], y_train, y_test
    )


if __name__ == "__main__":
    main()
