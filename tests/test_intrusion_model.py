
import pandas as pd

from scripts.detect_intrusions import TARGET, DROP_COLUMNS


def test_target_is_not_an_input_feature():
    df = pd.read_csv("data/cybersecurity_intrusion_data.csv", nrows=5)

    features = df.drop(columns=DROP_COLUMNS, errors="ignore").columns

    assert TARGET not in features
    assert "session_id" not in features


def test_dataset_has_expected_columns():
    df = pd.read_csv("data/cybersecurity_intrusion_data.csv")

    expected = {
        "session_id",
        "failed_logins",
        "login_attempts",
        "attack_detected",
    }

    assert expected.issubset(set(df.columns))


def test_target_has_both_classes():
    df = pd.read_csv("data/cybersecurity_intrusion_data.csv")

    assert set(df["attack_detected"].dropna().unique()) == {0, 1}
