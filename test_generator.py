import requests
import random
import time
from datetime import datetime

API_URL = "http://localhost:5000/api/ingest"

SAMPLE_IPS = [
    "192.168.1.100", "192.168.1.101", "10.0.0.50",
    "192.168.100.25", "172.16.0.10", "203.0.113.45"
]

SAMPLE_EVENTS = [
    {"event_type": "login_failed", "action": "DENY", "message": "Failed login attempt"},
    {"event_type": "login_success", "action": "ALLOW", "message": "Successful login"},
    {"event_type": "port_scan", "action": "DETECT", "message": "Port scanning detected"},
    {"event_type": "privilege_escalation", "action": "ALERT", "message": "sudo command executed"},
    {"event_type": "file_access", "action": "ALLOW", "message": "File accessed"},
]

def generate_log():
    source_ip = random.choice(SAMPLE_IPS)
    event = random.choice(SAMPLE_EVENTS)
    
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "dest_ip": "10.0.1.100",
        "source_port": random.randint(1024, 65535),
        "dest_port": random.choice([22, 80, 443, 3389, 445]),
        "event_type": event["event_type"],
        "action": event["action"],
        "user": f"user{random.randint(1, 5)}",
        "message": event["message"]
    }
    return log

def send_log(log):
    try:
        response = requests.post(API_URL, json={"log_type": "json", "log": log})
        print(f"✓ Sent: {log['event_type']} from {log['source_ip']} - Alerts: {response.json().get('alerts_generated', 0)}")
    except Exception as e:
        print(f"✗ Error: {e}")

def simulate_brute_force():
    print("\n🔴 Simulating Brute Force Attack...")
    attacker_ip = "192.168.100.25"
    for i in range(7):
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": attacker_ip,
            "dest_ip": "10.0.1.100",
            "event_type": "login_failed",
            "action": "DENY",
            "user": "admin",
            "message": "Failed login attempt"
        }
        send_log(log)
        time.sleep(0.5)

def simulate_port_scan():
    print("\n🔴 Simulating Port Scan...")
    scanner_ip = "172.16.0.10"
    for port in range(20, 35):
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": scanner_ip,
            "dest_ip": "10.0.1.100",
            "dest_port": port,
            "event_type": "connection_attempt",
            "action": "DETECT",
            "message": f"Connection attempt to port {port}"
        }
        send_log(log)
        time.sleep(0.3)

def main():
    print("🚀 SOC Platform - Log Generator")
    print("=" * 50)
    
    while True:
        print("\n1. Generate random logs")
        print("2. Simulate brute force attack")
        print("3. Simulate port scan")
        print("4. Continuous random generation")
        print("5. Exit")
        
        choice = input("\nSelect option: ")
        
        if choice == "1":
            count = int(input("How many logs? "))
            for _ in range(count):
                send_log(generate_log())
                time.sleep(0.2)
        
        elif choice == "2":
            simulate_brute_force()
        
        elif choice == "3":
            simulate_port_scan()
        
        elif choice == "4":
            print("Generating logs continuously (Ctrl+C to stop)...")
            try:
                while True:
                    send_log(generate_log())
                    time.sleep(random.uniform(1, 3))
            except KeyboardInterrupt:
                print("\nStopped.")
        
        elif choice == "5":
            break

if __name__ == "__main__":
    main()
