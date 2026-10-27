# Mini SOC: Automated Threat Detection

A hands-on cybersecurity project for security log analysis, brute-force detection, and structured alert generation.

## Current Features

- Parses JSON Lines authentication events.
- Detects repeated authentication failures within a five-minute window.
- Generates JSON alerts with severity and investigation status.
- Uses synthetic training data.

## Technology Stack

- Python 3
- JSON Lines
- Ubuntu on WSL 2

## Run Locally

From the project root, run:

    python3 scripts/detect_bruteforce.py

The script reads `data/sample_auth.jsonl` and writes alerts to `reports/alerts.json`.

## Project Status

Early prototype. Real Windows event collection, automated tests, additional detection rules, and SIEM integration are planned.

## Disclaimer

The included sample events are synthetic training data. This project is intended for defensive cybersecurity learning in an authorized lab.

## Machine Learning Intrusion Detection

The project includes a Random Forest classifier that analyzes session-level
features and predicts whether a session is labeled as an attack.

### Dataset

- File: `cybersecurity_intrusion_data.csv`
- Records: 9,537
- Features include failed logins, login attempts, protocol type,
  session duration, IP reputation score, and encryption type.
- Target: `attack_detected`

### Initial Evaluation

Evaluated using a stratified 75/25 train-test split.

| Metric | Initial result |
|---|---:|
| Accuracy | 88.3% |
| Precision (attack class) | 98.6% |
| Recall (attack class) | 75.0% |
| F1-score (attack class) | 85.2% |

Confusion matrix (rows = actual, columns = predicted):

| | Predicted normal | Predicted attack |
|---|---:|---:|
| Actual normal | 1,308 | 11 |
| Actual attack | 267 | 799 |

### Limitations

These results apply only to this dataset and split. The dataset's
label-generation process has not been independently verified, and some
features may be correlated with the target label. These metrics should
not be interpreted as real-world SOC detection accuracy.

### Run the Model

```bash
python scripts/detect_intrusions.py
```

The evaluation report is saved to `reports/intrusion_model_report.json`.

### Run Tests

```bash
python -m pytest -v
```
