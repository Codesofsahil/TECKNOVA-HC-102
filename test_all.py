"""
Comprehensive Test Suite - All Features
Tests: Core, Batch 1, Batch 2, Batch 3
"""

import requests
import json
import time

URL = "http://localhost:5000"

def print_section(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def test_result(name, success, details=""):
    status = "✓" if success else "✗"
    print(f"{status} {name}")
    if details:
        print(f"  {details}")

print_section("SOC PLATFORM - COMPREHENSIVE TEST SUITE")

# ============================================================================
# CORE FEATURES
# ============================================================================
print_section("1. CORE FEATURES")

# Test stats
try:
    r = requests.get(f"{URL}/api/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Dashboard Stats", True, f"Logs: {data['total_logs']}, Alerts: {data['total_alerts']}")
    else:
        test_result("Dashboard Stats", False)
except Exception as e:
    test_result("Dashboard Stats", False, str(e))

# Test alerts
try:
    r = requests.get(f"{URL}/api/alerts")
    test_result("Get Alerts", r.status_code == 200, f"Found {len(r.json())} alerts")
except:
    test_result("Get Alerts", False)

# Test incidents
try:
    r = requests.get(f"{URL}/api/incidents")
    test_result("Get Incidents", r.status_code == 200, f"Found {len(r.json())} incidents")
except:
    test_result("Get Incidents", False)

# ============================================================================
# BATCH 1: NOTIFICATIONS, GEO, EXPORT, SEARCH
# ============================================================================
print_section("2. BATCH 1 - Enhanced Features")

# Email config
try:
    r = requests.post(f"{URL}/api/notifications/configure", json={
        "type": "email",
        "from_email": "soc@test.com",
        "recipients": ["admin@test.com"]
    })
    test_result("Email Notifications", r.status_code == 200)
except:
    test_result("Email Notifications", False)

# Slack config
try:
    r = requests.post(f"{URL}/api/notifications/configure", json={
        "type": "slack",
        "webhook_url": "https://hooks.slack.com/test"
    })
    test_result("Slack Notifications", r.status_code == 200)
except:
    test_result("Slack Notifications", False)

# Geolocation
try:
    r = requests.get(f"{URL}/api/geolocation/attacks")
    test_result("Geolocation Map", r.status_code == 200, f"{len(r.json())} attacks mapped")
except:
    test_result("Geolocation Map", False)

# Export
try:
    r = requests.get(f"{URL}/api/export/alerts")
    test_result("CSV Export", r.status_code == 200, f"{len(r.text)} bytes")
except:
    test_result("CSV Export", False)

# Search
try:
    r = requests.post(f"{URL}/api/search", json={"query": "brute", "type": "alerts"})
    test_result("Advanced Search", r.status_code == 200)
except:
    test_result("Advanced Search", False)

# Threat Feed
try:
    r = requests.get(f"{URL}/api/threat-feed/192.168.100.25")
    if r.status_code == 200:
        data = r.json()
        test_result("Threat Intelligence", True, f"Threat Level: {data['threat_level']}")
    else:
        test_result("Threat Intelligence", False)
except:
    test_result("Threat Intelligence", False)

# Theme
try:
    r = requests.post(f"{URL}/api/theme", json={"theme": "dark"})
    test_result("Theme Manager", r.status_code == 200)
except:
    test_result("Theme Manager", False)

# ============================================================================
# BATCH 2: AUTH, REPORTS, VULN, NETWORK
# ============================================================================
print_section("3. BATCH 2 - Enterprise Features")

# Authentication
try:
    r = requests.post(f"{URL}/api/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    if r.status_code == 200:
        token = r.json().get('token')
        test_result("Authentication", True, f"Role: {r.json().get('role')}")
        
        # Verify token
        r2 = requests.get(f"{URL}/api/auth/verify", headers={"Authorization": f"Bearer {token}"})
        test_result("Token Verification", r2.status_code == 200)
    else:
        test_result("Authentication", False)
        token = None
except:
    test_result("Authentication", False)
    token = None

# Reports
try:
    r = requests.get(f"{URL}/api/reports/executive")
    if r.status_code == 200:
        data = r.json()
        test_result("Executive Report", True, f"Alerts: {data['summary']['total_alerts']}")
    else:
        test_result("Executive Report", False)
except:
    test_result("Executive Report", False)

# Vulnerability Scan
try:
    r = requests.post(f"{URL}/api/vulnerability/scan", json={"target": "192.168.1.100"})
    if r.status_code == 200:
        data = r.json()
        test_result("Vulnerability Scan", True, f"Found {data['total_vulnerabilities']} vulns")
    else:
        test_result("Vulnerability Scan", False)
except:
    test_result("Vulnerability Scan", False)

# Network Monitor
try:
    r = requests.post(f"{URL}/api/network/block", json={
        "ip": "192.168.100.25",
        "reason": "Test block"
    })
    test_result("Network Blocking", r.status_code == 200)
    
    r2 = requests.get(f"{URL}/api/network/stats")
    if r2.status_code == 200:
        data = r2.json()
        test_result("Network Stats", True, f"Blocked IPs: {data['blocked_ips_count']}")
    else:
        test_result("Network Stats", False)
except:
    test_result("Network Monitor", False)

# ============================================================================
# BATCH 3: ML, BACKUP, RATE LIMIT, AUDIT
# ============================================================================
print_section("4. BATCH 3 - Advanced Features")

# ML Prediction
try:
    r = requests.post(f"{URL}/api/ml/predict", json={
        "failed_attempts": 5,
        "unusual_time": True,
        "new_location": True
    })
    if r.status_code == 200:
        data = r.json()
        test_result("ML Threat Prediction", True, f"Score: {data['threat_score']}, Risk: {data['risk_level']}")
    else:
        test_result("ML Threat Prediction", False)
except:
    test_result("ML Threat Prediction", False)

# Threat Trends
try:
    r = requests.get(f"{URL}/api/ml/trends")
    if r.status_code == 200:
        data = r.json()
        test_result("Threat Trends", True, f"Direction: {data['trend_direction']}")
    else:
        test_result("Threat Trends", False)
except:
    test_result("Threat Trends", False)

# Backup
try:
    r = requests.post(f"{URL}/api/backup/create", json={"type": "alerts"})
    if r.status_code == 200:
        data = r.json()
        test_result("Backup Creation", True, f"ID: {data['backup_id']}")
    else:
        test_result("Backup Creation", False)
    
    r2 = requests.get(f"{URL}/api/backup/stats")
    if r2.status_code == 200:
        data = r2.json()
        test_result("Backup Stats", True, f"Total: {data['total_backups']}")
    else:
        test_result("Backup Stats", False)
except:
    test_result("Backup System", False)

# Audit Logging
try:
    r = requests.get(f"{URL}/api/audit/logs")
    if r.status_code == 200:
        logs = r.json()
        test_result("Audit Logs", True, f"{len(logs)} entries")
    else:
        test_result("Audit Logs", False)
    
    r2 = requests.get(f"{URL}/api/audit/user/admin")
    if r2.status_code == 200:
        data = r2.json()
        test_result("User Activity", True, f"{data['total_actions']} actions")
    else:
        test_result("User Activity", False)
except:
    test_result("Audit Logging", False)

# Rate Limiting
try:
    r = requests.get(f"{URL}/api/rate-limit/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Rate Limiter", True, f"Active IPs: {data['active_ips']}")
    else:
        test_result("Rate Limiter", False)
except:
    test_result("Rate Limiter", False)

# ============================================================================
# SUMMARY
# ============================================================================
print_section("TEST SUMMARY")

print("\n✅ Test Categories:")
print("  1. Core Features (3 tests)")
print("  2. Batch 1 - Enhanced (7 tests)")
print("  3. Batch 2 - Enterprise (6 tests)")
print("  4. Batch 3 - Advanced (7 tests)")
print("\nTotal: 23+ comprehensive tests")

print("\n📊 Platform Stats:")
print("  Features: 58")
print("  API Endpoints: 55")
print("  Services: 15")
print("  Detection Rules: 6+")

print("\n🎯 Quick Commands:")
print("  Start: python app.py")
print("  Test: python test_all.py")
print("  Generate Data: python test_generator.py")

print("\n" + "=" * 70)
print("✅ COMPREHENSIVE TEST COMPLETE")
print("=" * 70)
 COMPLETE!")
print("=" * 70)
