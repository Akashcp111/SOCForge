class ResponseEngine:
    def execute_response(self, alert):
        """
        Executes automated response actions based on alert type.
        
        Args:
            alert (dict): The alert dictionary containing the rule name and details.
        """
        rule_name = alert.get('rule_name', '')
        
        print(f"⚡ INITIATING RESPONSE for: {rule_name}")
        
        if "Brute Force" in rule_name:
            # Extract Source IP if available
            # In our threshold rule, we stored logs summary. 
            # We might need to look deeper or just simulate generic blocking.
            print("  [Action] Blocking Source IP on Firewall (Simulated)... DONE")
            print("  [Action] Locking User Account (Simulated)... DONE")
            
        elif "Malicious Process" in rule_name:
            print("  [Action] Isolating Host from Network (Simulated)... DONE")
            print("  [Action] Terminating Malicious Process (Simulated)... DONE")
            
        elif "Suspicious Web" in rule_name:
            print("  [Action] Blocking IP on WAF (Simulated)... DONE")
            
        else:
            print("  [Action] No automated response defined. Escalating to Analyst.")
