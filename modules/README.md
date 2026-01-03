# SOCForge Modules Documentation

This directory contains the core functional modules of the SOCForge framework.

## 1. Log Ingestion (`ingestion.py`)
**Purpose**: Handles the reading, parsing, and normalization of raw logs.
- **Key Class**: `LogIngestor`
- **Functionality**:
    - Reads logs from a file.
    - Uses Regular Expressions (Regex) to parse standard log formats (Timestamp, Level, Source, Message).
    - Normalizes data into a list of dictionaries.
    - Handles parsing errors gracefully.

## 2. Detection Engine (`detection.py`)
**Purpose**: Applies security rules to identifying malicious activity.
- **Key Class**: `DetectionEngine`
- **Functionality**:
    - Loads rules from `config/rules.json`.
    - Supports **Keyword Matching** (e.g., "mimikatz").
    - Supports **Threshold Detection** (e.g., 5 failed logins in 60s).
    - Sliding window logic for temporal correlation.

## 3. Threat Intelligence Enrichment (`enrichment.py`)
**Purpose**: Adds context to alerts using external or internal threat data.
- **Key Class**: `ThreatIntel`
- **Functionality**:
    - Extracts IP addresses from log messages.
    - Queries a threat database (simulated or API-based) for reputation scores.
    - Appends threat data (Country, Attacks, Reputation) to alerts.

## 4. Alerting & Reporting (`alerting.py`)
**Purpose**: Manages the distribution of security alerts.
- **Key Class**: `AlertManager`
- **Functionality**:
    - Formats alerts for display.
    - Logs alerts to `logs/alerts.log`.
    - Sends email notifications via SMTP (configurable).

## 5. Response Engine (`response.py`)
**Purpose**: Executes automated containment and mitigation actions.
- **Key Class**: `ResponseEngine`
- **Functionality**:
    - Maps alert types to response actions.
    - Simulates actions such as:
        - Blocking IPs on Firewalls.
        - Locking User Accounts.
        - Isolating Hosts.
