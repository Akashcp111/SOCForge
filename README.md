# SOCForge

SOCForge is a Python-based security automation framework designed for SOC operations. It automates log parsing, rule-based detection, threat intelligence enrichment, alerting, and simulated response actions.

## Features

- **Log Ingestion**: Parses logs from various sources.
- **Rule-Based Detection**: Identifies anomalies and malicious patterns.
- **Threat Intelligence**: Enriches events with external data.
- **Alerting**: Sends notifications for detected threats.
- **Response**: Simulates automated response actions.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Configure `config/config.json` and `config/rules.json`.
3. (Optional) Generate fresh logs for testing:
   ```bash
   python utils/log_generator.py
   ```
4. Run the application:
   ```bash
   python main.py
   ```

## Live Demonstration

To run a full demonstration:
1. Run `python utils/log_generator.py` to create `logs/sample.log` with current timestamps.
2. Run `python main.py` to ingest these logs, detect threats, and trigger responses.
