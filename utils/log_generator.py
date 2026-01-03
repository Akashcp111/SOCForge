import random
import time
from datetime import datetime, timedelta

def generate_logs(output_file="logs/sample.log", count=20):
    """
    Generates a set of logs including normal activity and simulated attacks.
    Updates timestamps to be 'current' for effective testing of time-window rules.
    """
    print(f"Generating {count} logs to {output_file}...")
    
    base_time = datetime.now()
    
    # Templates for different log types
    logs = []
    
    # 1. Normal Activity
    for i in range(count // 2):
        t = base_time - timedelta(minutes=random.randint(1, 10))
        ts = t.strftime('%Y-%m-%d %H:%M:%S')
        logs.append(f"{ts} INFO [System] User: user_{random.randint(1,5)} Logon Success")

    # 2. Brute Force Attack (5 failures in < 1 min)
    attack_time = base_time - timedelta(seconds=30)
    for i in range(6):
        t = attack_time + timedelta(seconds=i*2)
        ts = t.strftime('%Y-%m-%d %H:%M:%S')
        logs.append(f"{ts} WARN [Security] EventID: 4625 User: admin Source: 192.168.1.11 Logon Failed")

    # 3. Malicious Process
    t = base_time - timedelta(minutes=1)
    ts = t.strftime('%Y-%m-%d %H:%M:%S')
    logs.append(f"{ts} INFO [System] Process: mimikatz.exe started by user alice")

    # 4. LFI Attack
    t = base_time - timedelta(minutes=2)
    ts = t.strftime('%Y-%m-%d %H:%M:%S')
    logs.append(f"{ts} ERROR [Web] 192.168.1.60 - - [{t.strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET /index.php?page=../../../../etc/passwd HTTP/1.1\" 404 456")

    # Sort by time
    # (Simple sort by string works for ISO-like format at start, but LFI has different internal format, 
    # but the prefix timestamp is what we use for ingestion)
    logs.sort()
    
    with open(output_file, 'w') as f:
        for log in logs:
            f.write(log + "\n")
            
    print("Logs generated successfully.")

if __name__ == "__main__":
    generate_logs()
