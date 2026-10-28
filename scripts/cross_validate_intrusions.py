
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import make_scorer, f1_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

DATA_FILE = "data/cybersecurity_intrusion_data.csv"


def main():
    df = pd.read_csv(DATA_FILE).dropna(subset=["attack_detected"])

    y = df["attack_detected"].astype(int)
    X = df.drop(columns=["attack_detected", "session_id"], errors="ignore")

    numeric_cols = X.select_dtypes(include="number").columns.tolist()
    categorical_cols = X.select_dtypes(exclude="number").columns.tolist()

    preprocessor = ColumnTransformer([
        ("numeric", SimpleImputer(strategy="median"), numeric_cols),
        ("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical_cols),
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

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    results = cross_validate(
        model,
        X,
        y,
        cv=cv,
        scoring={
            "accuracy": "accuracy",
            "precision": "precision",
            "recall": make_scorer(recall_score, zero_division=0),
            "f1": make_scorer(f1_score, zero_division=0),
        },
        n_jobs=1,
        return_train_score=False,
    )

    print("5-fold stratified cross-validation")
    print(f"Records: {len(df)}")

    for metric in ("accuracy", "precision", "recall", "f1"):
        scores = results[f"test_{metric}"]
        print(
            f"{metric.capitalize():10s}: "
            f"mean={scores.mean():.3f}, "
            f"std={scores.std():.3f}, "
            f"folds={[round(float(s), 3) for s in scores]}"
        )


if __name__ == "__main__":
    main()
