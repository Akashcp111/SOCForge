import re
import pandas as pd
from datetime import datetime

class LogIngestor:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        # Regex to parse the sample log format: YYYY-MM-DD HH:MM:SS LEVEL [Source] Message
        self.log_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+\[(.*?)\]\s+(.*)$')

    def ingest_logs(self):
        """
        Reads the log file and parses it into a list of dictionaries.
        
        Returns:
            list: A list of dictionaries, where each dictionary represents a parsed log entry.
                  Returns an empty list if the file is not found or an error occurs.
        """
        parsed_logs = []
        try:
            with open(self.log_file_path, 'r') as file:
                for line in file:
                    match = self.log_pattern.match(line.strip())
                    if match:
                        timestamp_str, level, source, message = match.groups()
                        parsed_logs.append({
                            'timestamp': timestamp_str,
                            'level': level,
                            'source': source,
                            'message': message,
                            'original_log': line.strip()
                        })
                    else:
                        # Fallback for lines that don't match strict format
                        parsed_logs.append({
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'level': 'UNKNOWN',
                            'source': 'UNKNOWN',
                            'message': line.strip(),
                            'original_log': line.strip()
                        })
            
            print(f"Successfully ingested {len(parsed_logs)} log entries.")
            return parsed_logs
        
        except FileNotFoundError:
            print(f"Error: Log file not found at {self.log_file_path}")
            return []
        except Exception as e:
            print(f"Error ingesting logs: {e}")
            return []

    def to_dataframe(self, logs):
        """
        Converts the list of log dictionaries to a pandas DataFrame.
        
        Args:
            logs (list): A list of log dictionaries.
            
        Returns:
            pd.DataFrame: A pandas DataFrame containing the log data.
        """
        return pd.DataFrame(logs)
