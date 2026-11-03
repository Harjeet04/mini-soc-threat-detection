# Mini SOC — Security Monitoring and Threat Detection

A Python-based Mini Security Operations Center (SOC) that brings together Windows authentication monitoring, rule-based brute-force detection, machine-learning intrusion predictions, and security alert investigation in a Streamlit dashboard.

This project was developed as a hands-on cybersecurity portfolio project to demonstrate security log analysis, detection engineering, Python automation, and basic SOC investigation workflows.

## Features

### 1. Security Monitoring Dashboard
- Interactive Streamlit dashboard.
- Overview of authentication events and detection results.
- Summary metrics and visualizations.
- Separate pages for Windows Authentication, Security Alerts, and ML Detection.

### 2. Windows Authentication Monitoring
- Processes Windows Security authentication events.
- Supports Event ID 4624 (successful logon) and 4625 (failed logon).
- Normalizes collected events into JSON Lines (JSONL).
- Displays authentication activity and supports filtering.
- Shows failed logon activity by account.

### 3. Rule-Based Brute-Force Detection
- Detects five failed logons within a five-minute window.
- Groups remote authentication failures by source IP where available.
- Uses account and computer context for certain local events.
- Generates structured JSON alerts.
- Includes detection logic for unattributed events and successful logons.

### 4. Security Alert Investigation
- Displays Windows rule-based alerts.
- Provides alert details such as source IP, target account, failure count, severity, and detection reason when available.
- Supports inspection of raw alert JSON.
- Separates synthetic demonstration alerts from collected Windows events.

### 5. Machine-Learning Intrusion Detection
- Uses a Random Forest classification pipeline.
- Analyzes session-level network and authentication features.
- Supports model training and scoring of new session data.
- Generates attack predictions and probability scores.
- Assigns illustrative severity levels to predictions.
- Displays prediction details in the dashboard.

### 6. Automated Testing
- Unit tests for brute-force detection.
- Tests for Windows event normalization and detection.
- Tests for alert generation and ML scoring.
- Streamlit dashboard page tests.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Detection logic and automation |
| Streamlit | Interactive SOC dashboard |
| Pandas | Log and dataset processing |
| Scikit-learn | Machine-learning classification |
| JSON / JSONL | Event and alert storage |
| PowerShell | Windows Security event collection |
| Pytest | Automated testing |
| WSL 2 / Ubuntu | Development environment |
| Git / GitHub | Version control |

## Project Structure

```text
mini-soc/
├── app.py
├── scripts/
│   ├── detect_bruteforce.py
│   ├── normalize_windows_logs.py
│   ├── detect_windows_bruteforce.py
│   ├── generate_alerts.py
│   ├── train_model.py
│   ├── score_sessions.py
│   └── detect_intrusions.py
├── data/
│   ├── sample_auth.jsonl
│   ├── demo_auth_events.jsonl
│   ├── sample_sessions.csv
│   └── normalized_auth.jsonl
├── reports/
│   ├── alerts.json
│   ├── windows_alerts.json
│   ├── ml_alerts.json
│   └── scored_sessions.json
├── tests/
│   ├── test_detector.py
│   ├── test_dashboard.py
│   └── ...
├── models/
├── requirements.txt
├── .gitignore
└── README.md
```

Some generated files, datasets, and model artifacts may be excluded from Git through `.gitignore`.

## Installation

### Prerequisites
- Python 3.10 or newer
- pip
- Git
- Ubuntu / WSL 2 or another supported Python environment

### 1. Clone the repository

```bash
git clone https://github.com/Harjeet04/mini-soc-threat-detection.git
cd mini-soc-threat-detection
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

### Launch the SOC dashboard

```bash
streamlit run app.py
```

Open the local URL printed in the terminal, normally:

```text
http://localhost:8501
```

### Run the basic brute-force detector

```bash
python scripts/detect_bruteforce.py
```

The detector processes the sample authentication log and saves its alerts to:

```text
reports/alerts.json
```

### Normalize Windows authentication events

After collecting and placing the Windows event export in the expected data location:

```bash
python scripts/normalize_windows_logs.py
```

Normalized events are written to:

```text
data/normalized_auth.jsonl
```

### Detect Windows brute-force activity

```bash
python scripts/detect_windows_bruteforce.py
```

The resulting report is saved to:

```text
reports/windows_alerts.json
```

### Train the machine-learning model

```bash
python scripts/train_model.py
```

### Score session data

```bash
python scripts/score_sessions.py --input data/sample_sessions.csv
```

### Generate ML alerts

```bash
python scripts/generate_alerts.py
```

The generated ML alert report is saved to:

```text
reports/ml_alerts.json
```

## Detection Logic

The Windows brute-force detector uses a threshold of five failed logons within five minutes.

The detector examines available attribution information, including source IP, account, computer, and logon type. Events without sufficient attribution are excluded from grouping.

The machine-learning pipeline uses a Random Forest classifier to produce session-level predictions. Its predictions are separate from the Windows rule-based alerts.

## Testing

Run the complete automated test suite:

```bash
python -m pytest -q
```

Latest verified result during development:

**35 passed, 0 failed.**

The test suite includes detection logic, dashboard loading, alert generation, and other project components.

Some third-party Pandas/Streamlit deprecation warnings may still appear. They do not indicate test failures.

## Machine-Learning Evaluation

The intrusion detection model was evaluated on a public dataset using a stratified train-test split.

An evaluated threshold of 0.40 produced the following results:

| Metric | Result |
|---|---:|
| Accuracy | 86.8% |
| Attack precision | 93.4% |
| Attack recall | 75.9% |
| Attack F1-score | 84.3% |
| False positives | 57 |
| False negatives | 257 |

These results apply only to the selected dataset and evaluation procedure. They are not evidence of equivalent performance against real-world attacks.

## Security and Data Handling

- Use only systems and logs that you own or are authorized to analyze.
- Sample and synthetic events are intended for demonstration and testing.
- Do not commit real usernames, IP addresses, authentication records, credentials, or other sensitive log data.
- Keep private datasets and generated model artifacts out of public repositories.
- Review `.gitignore` before committing changes.

## Limitations

- This is a local Mini SOC prototype, not a production SIEM.
- Detection rules use fixed thresholds and may generate false positives.
- Windows event attribution depends on the fields available in collected events.
- ML predictions are dataset-dependent and do not independently confirm malicious activity.
- The project does not currently provide continuous enterprise-wide monitoring or automated incident response.

## Future Improvements

- Add more Windows Security event detection rules.
- Improve alert correlation and prioritization.
- Add additional log sources and detection use cases.
- Improve ML evaluation using independent datasets.
- Add alert export and analyst reporting features.
- Explore integration with SIEM platforms such as Splunk or Wazuh.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. It is not a replacement for an enterprise SIEM or a validated security monitoring solution.
