import requests
import re

class ThreatIntel:
    def __init__(self, api_key=None):
        self.api_key = api_key
        # Simulated database of malicious IPs for demonstration
        self.malicious_ips = {
            "192.168.1.60": {"reputation": "Bad", "country": "Unknown", "attacks": ["LFI", "Scanner"]},
            "192.168.1.11": {"reputation": "Suspicious", "country": "Internal", "attacks": ["Brute Force"]}
        }

    def extract_ips(self, text):
        """
        Extracts IPv4 addresses from a string using regex.
        
        Args:
            text (str): The text content to search (e.g., log message).
            
        Returns:
            list: A list of unique IP addresses found in the text.
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))

    def check_ip(self, ip):
        """
        Checks IP reputation. In a real scenario, this would query VirusTotal or AbuseIPDB.
        
        Args:
            ip (str): The IP address to check.
            
        Returns:
            dict: Threat intelligence data (reputation, country, attacks).
        """
        if self.api_key and self.api_key != "YOUR_API_KEY_HERE":
            # Placeholder for real API call
            # response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": self.api_key})
            # return response.json()
            pass
        
        # Return simulated data
        return self.malicious_ips.get(ip, {"reputation": "Clean", "country": "Unknown"})

    def enrich_alerts(self, alerts):
        """
        Enriches a list of alerts with threat intelligence data.
        """
        enriched_alerts = []
        for alert in alerts:
            # Extract IPs from the log message or source
            # Assuming 'log' key exists and has 'message' or 'source'
            content_to_scan = ""
            if 'log' in alert:
                content_to_scan += alert['log'].get('message', '') + " " + alert['log'].get('source', '')
            elif 'logs' in alert:
                content_to_scan += " ".join(alert['logs'])
            
            ips = self.extract_ips(content_to_scan)
            threat_data = {}
            for ip in ips:
                info = self.check_ip(ip)
                if info['reputation'] != 'Clean':
                    threat_data[ip] = info
            
            if threat_data:
                alert['threat_intel'] = threat_data
            
            enriched_alerts.append(alert)
        
        return enriched_alerts
