import requests
import random
from datetime import datetime
import time

API_URL = "http://localhost:5000/api/ingest"

SAMPLE_IPS = ["192.168.1.100", "192.168.1.101", "10.0.0.50", "192.168.100.25", "172.16.0.10"]
EVENTS = ["login_failed", "login_success", "port_scan", "privilege_escalation", "file_access"]

print("Generating 20 test logs...")

for i in range(20):
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": random.choice(SAMPLE_IPS),
        "dest_ip": "10.0.1.100",
        "event_type": random.choice(EVENTS),
        "action": random.choice(["ALLOW", "DENY", "DETECT"]),
        "user": f"user{random.randint(1, 5)}",
        "message": f"Test event {i+1}"
    }
    
    try:
        response = requests.post(API_URL, json={"log_type": "json", "log": log})
        print(f"Log {i+1}/20 sent - Alerts: {response.json().get('alerts_generated', 0)}")
    except Exception as e:
        print(f"Error: {e}")
    
    time.sleep(0.2)

print("\nDone! Refresh your dashboard.")
