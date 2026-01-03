import json
import os
from modules.ingestion import LogIngestor
from modules.detection import DetectionEngine
from modules.enrichment import ThreatIntel
from modules.alerting import AlertManager
from modules.response import ResponseEngine

def load_config(config_path="config/config.json"):
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file not found at {config_path}")
        return {}
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}

def main():
    print("Starting SOCForge Security Automation Framework...")
    
    # 1. Load Configuration
    config = load_config()
    if not config:
        return

    # 2. Initialize Modules
    ingestor = LogIngestor(config.get('log_file_path', 'logs/sample.log'))
    detector = DetectionEngine('config/rules.json')
    intel = ThreatIntel(config.get('virustotal_api_key'))
    alerter = AlertManager(config)
    responder = ResponseEngine()

    # 3. Ingest Logs
    print("\n--- Phase 1: Log Ingestion ---")
    logs = ingestor.ingest_logs()
    if not logs:
        print("No logs to process. Exiting.")
        return

    # 4. Detect Threats
    print("\n--- Phase 2: Detection ---")
    alerts = detector.detect_threats(logs)
    print(f"Detected {len(alerts)} potential threats.")

    if not alerts:
        print("No threats detected.")
        return

    # 5. Enrich Alerts
    print("\n--- Phase 3: Threat Intelligence Enrichment ---")
    enriched_alerts = intel.enrich_alerts(alerts)

    # 6. Alerting and Response
    print("\n--- Phase 4: Alerting & Response ---")
    for alert in enriched_alerts:
        alerter.send_alert(alert)
        responder.execute_response(alert)
        
    print("\nSOCForge execution completed.")

if __name__ == "__main__":
    main()
