import smtplib
from email.mime.text import MIMEText
import json
import datetime

class AlertManager:
    def __init__(self, config):
        self.config = config
        self.alert_log_path = "logs/alerts.log"

    def send_alert(self, alert):
        """
        Dispatches the alert to configured channels (Console, File, Email).
        
        Args:
            alert (dict): The alert dictionary containing details of the threat.
        """
        self._print_alert(alert)
        self._log_alert_to_file(alert)
        
        # Uncomment to enable email alerting
        # self._send_email_alert(alert)

    def _print_alert(self, alert):
        print("\n" + "="*50)
        print(f"🚨 ALERT: {alert['rule_name']}")
        print(f"Severity: {alert.get('severity', 'Medium')}")
        print(f"Timestamp: {alert.get('timestamp')}")
        print(f"Description: {alert.get('description')}")
        
        if 'threat_intel' in alert:
            print("⚠️ Threat Intelligence Match:")
            print(json.dumps(alert['threat_intel'], indent=2))
        
        print("="*50 + "\n")

    def _log_alert_to_file(self, alert):
        try:
            with open(self.alert_log_path, 'a') as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            print(f"Error logging alert to file: {e}")

    def _send_email_alert(self, alert):
        try:
            msg = MIMEText(json.dumps(alert, indent=4))
            msg['Subject'] = f"SOCForge Alert: {alert['rule_name']}"
            msg['From'] = self.config.get('email_user')
            msg['To'] = self.config.get('report_email')

            server = smtplib.SMTP(self.config.get('smtp_server'), self.config.get('smtp_port'))
            server.starttls()
            server.login(self.config.get('email_user'), self.config.get('email_password'))
            server.send_message(msg)
            server.quit()
            print("Email alert sent successfully.")
        except Exception as e:
            print(f"Failed to send email alert: {e}")
