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

## Model Comparison and Baseline Analysis

All models were evaluated on the same stratified 75/25 train-test split
with `random_state=42`.

| Approach | Accuracy | Attack precision | Attack recall | Attack F1 |
|---|---:|---:|---:|---:|
| Rule: failed_logins >= 3 | 71.3% | 100.0% | 35.8% | 0.53 |
| Random Forest (2 login features) | 79.7% | 100.0% | 54.5% | 0.71 |
| Random Forest (all features) | 88.3% | 98.6% | 75.0% | 0.85 |
| Random Forest (without login features) | 59.8% | 56.0% | 46.0% | 0.51 |

### Interpretation

The full-feature Random Forest performed best on this test split.
Removing login-related features substantially reduced performance,
indicating that these features carry significant predictive information.

The simple threshold rule had high precision but low recall, missing
many attack-labeled records.

### Limitations

The dataset's label-generation process has not been independently
verified. Strong relationships between login features and attack
labels may reflect genuine patterns or dataset-generation rules.
These results are not evidence of equivalent performance on live
production systems.

## Threshold Evaluation

The Random Forest model was evaluated at a probability threshold of 0.40.
The threshold was selected using validation data before evaluating the
held-out test set.

### Held-out Test Results

| Metric | Result |
|---|---:|
| Accuracy | 86.8% |
| Attack precision | 93.4% |
| Attack recall | 75.9% |
| Attack F1-score | 84.3% |
| False positives | 57 |
| False negatives | 257 |

Confusion matrix (rows = actual, columns = predicted):

| | Predicted normal | Predicted attack |
|---|---:|---:|
| Actual normal | 1,262 | 57 |
| Actual attack | 257 | 809 |

### Interpretation

The lower threshold increases sensitivity to attacks but also produces
more false alerts. Threshold selection depends on the balance between
missed attacks and analyst workload.

These results apply only to this dataset and evaluation split. The
dataset's label-generation process has not been independently verified,
so the results should not be interpreted as real-world SOC accuracy.

## ML-Based Intrusion Detection and Alert Generation

The project includes a Random Forest classifier that analyzes session-level
features and generates structured JSON alerts for sessions predicted as attacks.

### Detection Pipeline

1. Load the public intrusion detection dataset.
2. Preprocess numeric and categorical features.
3. Train a Random Forest classifier.
4. Apply a probability threshold of 0.40.
5. Generate structured alerts for predicted attacks.
6. Save the alert report as JSON.
7. Run automated tests to validate detection components and alert structure.

### Dataset

- Records: 9,537
- Features include failed logins, login attempts, protocol type,
  session duration, IP reputation score, and encryption type.
- Target column: `attack_detected`
- The raw CSV is excluded from Git by `.gitignore`.

### Model Evaluation

The model was evaluated using a stratified 75/25 train-test split.

| Metric | Initial result |
|---|---:|
| Accuracy at threshold 0.40 | 86.8% |
| Attack precision | 93.4% |
| Attack recall | 75.9% |
| Attack F1-score | 84.3% |
| False positives | 57 |
| False negatives | 257 |

A separate five-fold stratified cross-validation experiment with the
default classification threshold reported mean accuracy of 89.0% and
mean attack F1-score of 86.2%.

These results come from different evaluation procedures and thresholds;
they should not be compared as if they were the same experiment.

### Threshold Analysis

Threshold tuning compared values from 0.30 to 0.70 using validation data.
A threshold of 0.40 was selected as a candidate to balance attack detection
and false alerts.

The threshold may need adjustment for other datasets or operational needs.

### Structured Alert Output

Run the alert generator:

```bash
python scripts/generate_alerts.py
```

The script writes alerts to:

`reports/ml_alerts.json`

Each alert contains:

- `session_id`: identifier for the dataset session
- `alert_type`: detection category
- `predicted_label`: predicted attack label
- `attack_probability`: model-estimated probability
- `threshold`: threshold used for the prediction
- `severity`: illustrative severity based on probability bands

The current implementation processes a held-out test split and is intended
for evaluation, not continuous production monitoring.

### Automated Tests

Run all tests:

```bash
python -m pytest -v
```

The test suite covers brute-force detection behavior, dataset and feature
checks, alert severity assignment, threshold configuration, and JSON report
validation.

### Limitations and Future Improvements

- The dataset's label-generation process has not been independently verified.
- Model probabilities do not prove that an attack occurred.
- Severity levels are illustrative and are not a validated risk standard.
- The dataset does not contain source IP addresses or event timestamps.
- The current alert generator evaluates a held-out split rather than
  processing live events.
- Future work includes inference on new sessions, Windows event-log
  ingestion, improved alert correlation, and evaluation on independent data.

## Model Training and Inference

The project supports separate model training and session scoring.

### Train the model

```bash
python scripts/train_model.py
```

The trained pipeline and its metadata are saved under `models/`.
The serialized model is excluded from Git.

### Score new sessions

Prepare a CSV containing the model's required input features.
The target column `attack_detected` should not be included.

```bash
python scripts/score_sessions.py --input data/sample_sessions.csv
```

Specify a custom output path if needed:

```bash
python scripts/score_sessions.py \
  --input data/sample_sessions.csv \
  --output reports/scored_sessions.json
```

The scorer loads the saved model without retraining and produces JSON
predictions with session IDs, attack probabilities, labels, and illustrative
severity levels.

### Testing

```bash
python -m pytest -v
```

The test suite currently covers brute-force detection, dataset checks,
alert generation, and saved-model inference.

### Operational limitations

The sample scoring file is derived from the public dataset and is intended
for pipeline testing, not independent validation. The model's labels and
performance have not been verified against real production attacks.

## Windows Security Log Integration

The project includes a Windows authentication-log collection and detection pipeline.

### Event Collection

A PowerShell script collects Windows Security events:

- Event ID 4624: Successful logon
- Event ID 4625: Failed logon

The collector extracts timestamps, account information, source IP addresses,
computer names, logon types, and authentication status codes where available.

### Log Normalization

Windows events are converted into normalized JSONL records using:

```bash
python scripts/normalize_windows_logs.py
```

### Windows Brute-Force Detection

Run the Windows-specific detector:

```bash
python scripts/detect_windows_bruteforce.py
```

Detection logic:

- Five failed logons within five minutes.
- Groups remote events by available source IP.
- Groups local events by account, computer, and logon type.
- Does not group events with insufficient attribution.

Alerts are saved to:

`reports/windows_alerts.json`

### Testing

The Windows detection module has automated tests covering:

- Repeated failures from the same IP.
- Repeated local account failures.
- Successful logons being ignored.
- Unattributed events being excluded.
- Failed logons outside the five-minute window.

Run the complete test suite:

```bash
python -m pytest -v
```

### Limitations

- Windows event collection currently uses a limited sample of recent events.
- Some Windows events do not contain a usable source IP.
- Account-context detections can produce false positives.
- Synthetic tests validate detection logic, not real-world attack detection.
- The current implementation is a local prototype, not a production SIEM.
