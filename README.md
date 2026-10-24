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
