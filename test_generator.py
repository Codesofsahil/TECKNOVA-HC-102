import requests
import random
import time
from datetime import datetime

API_URL = "http://localhost:5000/api/ingest"

SAMPLE_IPS = [
    "192.168.1.100", "192.168.1.101", "10.0.0.50",
<<<<<<< HEAD
    "192.168.100.25", "172.16.0.10", "203.0.113.45",
    "185.220.101.5", "45.142.214.8", "91.219.236.12"
=======
    "192.168.100.25", "172.16.0.10", "203.0.113.45"
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
]

SAMPLE_EVENTS = [
    {"event_type": "login_failed", "action": "DENY", "message": "Failed login attempt"},
    {"event_type": "login_success", "action": "ALLOW", "message": "Successful login"},
    {"event_type": "port_scan", "action": "DETECT", "message": "Port scanning detected"},
    {"event_type": "privilege_escalation", "action": "ALERT", "message": "sudo command executed"},
    {"event_type": "file_access", "action": "ALLOW", "message": "File accessed"},
<<<<<<< HEAD
    {"event_type": "sql_injection", "action": "BLOCK", "message": "SQL injection attempt detected"},
    {"event_type": "xss_attack", "action": "BLOCK", "message": "Cross-site scripting attempt"},
    {"event_type": "malware_detected", "action": "QUARANTINE", "message": "Malicious file detected"},
    {"event_type": "ddos_attack", "action": "MITIGATE", "message": "DDoS attack in progress"},
    {"event_type": "data_exfiltration", "action": "ALERT", "message": "Suspicious data transfer"},
    {"event_type": "phishing_attempt", "action": "BLOCK", "message": "Phishing email detected"},
    {"event_type": "ransomware", "action": "ISOLATE", "message": "Ransomware activity detected"},
    {"event_type": "lateral_movement", "action": "ALERT", "message": "Lateral movement detected"},
    {"event_type": "credential_stuffing", "action": "BLOCK", "message": "Credential stuffing attack"},
    {"event_type": "backdoor_access", "action": "ALERT", "message": "Backdoor communication detected"},
    {"event_type": "buffer_overflow", "action": "BLOCK", "message": "Buffer overflow attempt"},
    {"event_type": "dns_tunneling", "action": "ALERT", "message": "DNS tunneling detected"},
    {"event_type": "crypto_mining", "action": "BLOCK", "message": "Cryptocurrency mining detected"},
    {"event_type": "web_shell", "action": "QUARANTINE", "message": "Web shell uploaded"},
    {"event_type": "command_injection", "action": "BLOCK", "message": "Command injection attempt"},
=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
]

def generate_log():
    source_ip = random.choice(SAMPLE_IPS)
    event = random.choice(SAMPLE_EVENTS)
    
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "dest_ip": "10.0.1.100",
        "source_port": random.randint(1024, 65535),
<<<<<<< HEAD
        "dest_port": random.choice([22, 80, 443, 3389, 445, 21, 23, 25, 53, 135]),
=======
        "dest_port": random.choice([22, 80, 443, 3389, 445]),
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
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
<<<<<<< HEAD
    print("\nSimulating Brute Force Attack...")
=======
    print("\n🔴 Simulating Brute Force Attack...")
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
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
<<<<<<< HEAD
    print("\nSimulating Port Scan...")
=======
    print("\n🔴 Simulating Port Scan...")
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
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

<<<<<<< HEAD
def simulate_advanced_attacks():
    print("\nSimulating Advanced Persistent Threat...")
    apt_ip = "185.220.101.5"
    attacks = [
        {"event_type": "lateral_movement", "message": "SMB lateral movement detected"},
        {"event_type": "credential_stuffing", "message": "Password spray attack"},
        {"event_type": "data_exfiltration", "message": "Large data transfer to external IP"},
        {"event_type": "backdoor_access", "message": "C2 communication established"},
        {"event_type": "privilege_escalation", "message": "Admin privileges obtained"}
    ]
    
    for attack in attacks:
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": apt_ip,
            "dest_ip": "10.0.1.100",
            "event_type": attack["event_type"],
            "action": "ALERT",
            "user": "system",
            "message": attack["message"]
        }
        send_log(log)
        time.sleep(1)

def simulate_web_attacks():
    print("\nSimulating Web Application Attacks...")
    web_attacker = "45.142.214.8"
    web_attacks = [
        {"event_type": "sql_injection", "message": "SQL injection in login form"},
        {"event_type": "xss_attack", "message": "Reflected XSS attempt"},
        {"event_type": "command_injection", "message": "OS command injection"},
        {"event_type": "web_shell", "message": "PHP web shell upload attempt"},
        {"event_type": "buffer_overflow", "message": "Buffer overflow in web service"}
    ]
    
    for attack in web_attacks:
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": web_attacker,
            "dest_ip": "10.0.1.100",
            "dest_port": 80,
            "event_type": attack["event_type"],
            "action": "BLOCK",
            "message": attack["message"]
        }
        send_log(log)
        time.sleep(0.8)

def generate_critical_attacks():
    """Generate CRITICAL severity attacks"""
    print("\nGenerating CRITICAL Attacks...")
    critical_attacks = [
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "185.220.101.5",
            "dest_ip": "10.0.1.100",
            "event_type": "ransomware",
            "action": "ISOLATE",
            "severity": "CRITICAL",
            "message": "WannaCry ransomware detected - immediate isolation required"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "91.219.236.12",
            "dest_ip": "10.0.1.100",
            "event_type": "data_exfiltration",
            "action": "ALERT",
            "severity": "CRITICAL",
            "message": "Massive data exfiltration - 50GB transferred to external server"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "203.0.113.45",
            "dest_ip": "10.0.1.100",
            "event_type": "backdoor_access",
            "action": "ALERT",
            "severity": "CRITICAL",
            "message": "Advanced persistent threat - C2 server communication established"
        }
    ]
    
    for attack in critical_attacks:
        send_log(attack)
        time.sleep(1)

def generate_high_attacks():
    """Generate HIGH severity attacks"""
    print("\nGenerating HIGH Priority Attacks...")
    high_attacks = [
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "45.142.214.8",
            "dest_ip": "10.0.1.100",
            "event_type": "privilege_escalation",
            "action": "ALERT",
            "severity": "HIGH",
            "message": "Unauthorized privilege escalation - admin access gained"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "172.16.0.99",
            "dest_ip": "10.0.1.100",
            "event_type": "lateral_movement",
            "action": "ALERT",
            "severity": "HIGH",
            "message": "Lateral movement detected - compromised credentials used"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.100.50",
            "dest_ip": "10.0.1.100",
            "event_type": "malware_detected",
            "action": "QUARANTINE",
            "severity": "HIGH",
            "message": "Trojan.Emotet detected - banking credentials at risk"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "198.51.100.25",
            "dest_ip": "10.0.1.100",
            "event_type": "credential_stuffing",
            "action": "BLOCK",
            "severity": "HIGH",
            "message": "Large-scale credential stuffing attack - 10,000+ attempts"
        }
    ]
    
    for attack in high_attacks:
        send_log(attack)
        time.sleep(0.8)

def generate_medium_attacks():
    """Generate MEDIUM severity attacks"""
    print("\nGenerating MEDIUM Priority Attacks...")
    medium_attacks = [
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.150",
            "dest_ip": "10.0.1.100",
            "event_type": "sql_injection",
            "action": "BLOCK",
            "severity": "MEDIUM",
            "message": "SQL injection attempt on login form - blocked by WAF"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "10.0.0.75",
            "dest_ip": "10.0.1.100",
            "event_type": "xss_attack",
            "action": "BLOCK",
            "severity": "MEDIUM",
            "message": "Cross-site scripting attempt detected in user input"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "172.16.5.20",
            "dest_ip": "10.0.1.100",
            "event_type": "phishing_attempt",
            "action": "BLOCK",
            "severity": "MEDIUM",
            "message": "Phishing email with malicious attachment blocked"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.2.88",
            "dest_ip": "10.0.1.100",
            "event_type": "port_scan",
            "action": "DETECT",
            "severity": "MEDIUM",
            "message": "Comprehensive port scan detected - 1000+ ports scanned"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "203.0.113.100",
            "dest_ip": "10.0.1.100",
            "event_type": "dns_tunneling",
            "action": "ALERT",
            "severity": "MEDIUM",
            "message": "DNS tunneling detected - potential data exfiltration"
        }
    ]
    
    for attack in medium_attacks:
        send_log(attack)
        time.sleep(0.6)

def generate_low_attacks():
    """Generate LOW severity attacks"""
    print("\nGenerating LOW Priority Attacks...")
    low_attacks = [
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.25",
            "dest_ip": "10.0.1.100",
            "event_type": "login_success",
            "action": "ALLOW",
            "severity": "LOW",
            "message": "Successful login from unusual time - outside business hours"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "10.0.0.45",
            "dest_ip": "10.0.1.100",
            "event_type": "file_access",
            "action": "ALLOW",
            "severity": "LOW",
            "message": "Access to sensitive file directory - monitoring required"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "172.16.1.30",
            "dest_ip": "10.0.1.100",
            "event_type": "policy_violation",
            "action": "LOG",
            "severity": "LOW",
            "message": "Minor security policy violation - password complexity"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.5.12",
            "dest_ip": "10.0.1.100",
            "event_type": "suspicious_user_agent",
            "action": "LOG",
            "severity": "LOW",
            "message": "Unusual user agent string detected in web request"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "10.0.2.88",
            "dest_ip": "10.0.1.100",
            "event_type": "bandwidth_anomaly",
            "action": "MONITOR",
            "severity": "LOW",
            "message": "Slight increase in network bandwidth usage detected"
        },
        {
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.3.55",
            "dest_ip": "10.0.1.100",
            "event_type": "configuration_change",
            "action": "LOG",
            "severity": "LOW",
            "message": "Minor system configuration change detected"
        }
    ]
    
    for attack in low_attacks:
        send_log(attack)
        time.sleep(0.4)

def main():
    print("SOC Platform - Enhanced Attack Generator")
=======
def main():
    print("🚀 SOC Platform - Log Generator")
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    print("=" * 50)
    
    while True:
        print("\n1. Generate random logs")
        print("2. Simulate brute force attack")
        print("3. Simulate port scan")
<<<<<<< HEAD
        print("4. Simulate advanced persistent threat")
        print("5. Simulate web application attacks")
        print("6. Generate CRITICAL attacks")
        print("7. Generate HIGH priority attacks")
        print("8. Generate MEDIUM priority attacks")
        print("9. Generate LOW priority attacks")
        print("10. Generate ALL severity attacks")
        print("11. Full attack simulation (all types)")
        print("12. Continuous random generation")
        print("13. Exit")
=======
        print("4. Continuous random generation")
        print("5. Exit")
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
        
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
<<<<<<< HEAD
            
        elif choice == "4":
            simulate_advanced_attacks()
            
        elif choice == "5":
            simulate_web_attacks()
            
        elif choice == "6":
            generate_critical_attacks()
            
        elif choice == "7":
            generate_high_attacks()
            
        elif choice == "8":
            generate_medium_attacks()
            
        elif choice == "9":
            generate_low_attacks()
            
        elif choice == "10":
            print("\nGenerating attacks of all severities...")
            generate_critical_attacks()
            time.sleep(1)
            generate_high_attacks()
            time.sleep(1)
            generate_medium_attacks()
            time.sleep(1)
            generate_low_attacks()
            print("\nAll severity attacks generated!")
            
        elif choice == "11":
            print("\nRunning full attack simulation...")
            simulate_brute_force()
            time.sleep(2)
            simulate_port_scan()
            time.sleep(2)
            simulate_web_attacks()
            time.sleep(2)
            simulate_advanced_attacks()
            time.sleep(2)
            generate_critical_attacks()
            time.sleep(1)
            generate_high_attacks()
            time.sleep(1)
            generate_medium_attacks()
            time.sleep(1)
            generate_low_attacks()
            print("\nFull simulation complete!")
        
        elif choice == "12":
=======
        
        elif choice == "4":
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
            print("Generating logs continuously (Ctrl+C to stop)...")
            try:
                while True:
                    send_log(generate_log())
                    time.sleep(random.uniform(1, 3))
            except KeyboardInterrupt:
                print("\nStopped.")
        
<<<<<<< HEAD
        elif choice == "13":
            break

if __name__ == "__main__":
    main()
=======
        elif choice == "5":
            break

if __name__ == "__main__":
    main()
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
