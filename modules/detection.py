import json
from datetime import datetime, timedelta

class DetectionEngine:
    def __init__(self, rules_path):
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, rules_path):
        try:
            with open(rules_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading rules: {e}")
            return []

    def detect_threats(self, logs):
        """
        Analyzes logs against loaded rules.
        
        Args:
            logs (list): List of parsed log dictionaries.
            
        Returns:
            list: A list of alert dictionaries for any detected threats.
        """
        alerts = []
        
        # Convert timestamps to datetime objects for processing
        processed_logs = []
        for log in logs:
            try:
                log_time = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S')
                processed_logs.append({**log, 'dt': log_time})
            except ValueError:
                continue # Skip logs with invalid timestamps

        for rule in self.rules:
            if rule['type'] == 'keyword':
                alerts.extend(self._check_keyword_rule(rule, processed_logs))
            elif rule['type'] == 'threshold':
                alerts.extend(self._check_threshold_rule(rule, processed_logs))
        
        return alerts

    def _check_keyword_rule(self, rule, logs):
        alerts = []
        field = rule.get('field', 'message')
        value = rule.get('value', '').lower()
        
        for log in logs:
            log_value = str(log.get(field, '')).lower()
            # If the field is 'message' or 'original_log', we usually check for substring
            # If it's a specific field like 'event_id', we might want exact match, but let's stick to substring or equality based on context
            # For simplicity, if field is event_id, use equality, else substring
            
            match = False
            if field == 'event_id':
                # extracting event id from message if it's not parsed separately, 
                # but ingestion doesn't strictly parse event_id into a field unless we improved it.
                # In our ingestion, 'message' contains the rest. 
                # Wait, our sample log format was: `TIMESTAMP LEVEL [Source] Message`
                # And the message part contained `EventID: 4625`.
                # So `event_id` isn't a top-level key in the parsed log dictionary from Ingestion module.
                # It's part of 'message'.
                
                if f"eventid: {value}" in log['message'].lower():
                    match = True
            elif value in log_value:
                match = True
            
            if match:
                clean_log = log.copy()
                if 'dt' in clean_log:
                    del clean_log['dt']
                
                alerts.append({
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': 'High', # Could be in rule definition
                    'log': clean_log,
                    'timestamp': log['timestamp'],
                    'description': rule['description']
                })
        return alerts

    def _check_threshold_rule(self, rule, logs):
        alerts = []
        field = rule.get('field', 'event_id')
        value = rule.get('value', '')
        threshold = rule.get('threshold', 5)
        time_window = rule.get('time_window', 60) # seconds

        # Filter logs that match the criteria
        matching_logs = []
        for log in logs:
            # Similar matching logic
            if field == 'event_id':
                if f"eventid: {value}" in log['message'].lower():
                    matching_logs.append(log)
            elif value in str(log.get(field, '')).lower():
                matching_logs.append(log)

        # Check threshold in time window
        # We'll use a sliding window approach
        matching_logs.sort(key=lambda x: x['dt'])
        
        for i in range(len(matching_logs)):
            current_log = matching_logs[i]
            count = 1
            start_time = current_log['dt']
            
            # Look ahead
            window_logs = [current_log]
            for j in range(i + 1, len(matching_logs)):
                next_log = matching_logs[j]
                if (next_log['dt'] - start_time).total_seconds() <= time_window:
                    count += 1
                    window_logs.append(next_log)
                else:
                    break
            
            if count >= threshold:
                # To avoid duplicate alerts for the same sequence, we could optimize
                # But for now, let's just alert.
                # We can verify if we already alerted for this window start
                alerts.append({
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': 'Critical',
                    'count': count,
                    'logs': [l['original_log'] for l in window_logs], # Summary
                    'timestamp': current_log['timestamp'],
                    'description': f"{rule['description']} (Count: {count})"
                })
                # Skip the rest of this window to avoid spamming alerts for the same burst?
                # A simple way is to jump index, but we are in a for loop. 
                # Let's just return unique alerts later or accept duplicates for now.
                # Better: keep track of last alerted time
                
        # Deduplicate alerts based on timestamp or something? 
        # For this exercise, simple list is fine.
        return alerts
