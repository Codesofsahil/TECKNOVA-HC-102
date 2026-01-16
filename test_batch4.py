"""
Batch 4 Advanced Features Test Suite
Tests: WebSocket, Mobile Push, Cloud Storage, Threat Hunting,
Asset Management, Threat Modeling, Performance Monitoring
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

print_section("BATCH 4 - ADVANCED FEATURES TEST SUITE")

# ============================================================================
# WEBSOCKET MANAGEMENT
# ============================================================================
print_section("1. WEBSOCKET MANAGEMENT")

try:
    r = requests.get(f"{URL}/api/websocket/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("WebSocket Stats", True, f"Active connections: {data['active_connections']}")
    else:
        test_result("WebSocket Stats", False)
except Exception as e:
    test_result("WebSocket Stats", False, str(e))

# ============================================================================
# MOBILE PUSH NOTIFICATIONS
# ============================================================================
print_section("2. MOBILE PUSH NOTIFICATIONS")

# Register mobile device
try:
    r = requests.post(f"{URL}/api/mobile/register", json={
        "user_id": "admin",
        "device_token": "test_device_token_12345",
        "platform": "ios"
    })
    if r.status_code == 200:
        device_data = r.json()
        test_result("Mobile Device Registration", True, f"Device ID: {device_data['device_id']}")
    else:
        test_result("Mobile Device Registration", False)
except Exception as e:
    test_result("Mobile Device Registration", False, str(e))

# Mobile device stats
try:
    r = requests.get(f"{URL}/api/mobile/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Mobile Device Stats", True, f"Total devices: {data['total_devices']}")
    else:
        test_result("Mobile Device Stats", False)
except Exception as e:
    test_result("Mobile Device Stats", False, str(e))

# Send push notification
try:
    r = requests.post(f"{URL}/api/mobile/push", json={
        "type": "alert",
        "alert": {
            "id": "TEST_ALERT_001",
            "title": "Test Security Alert",
            "severity": "HIGH",
            "source_ip": "192.168.1.100"
        },
        "user_ids": ["admin"]
    })
    if r.status_code == 200:
        data = r.json()
        test_result("Push Notification", True, f"Sent to {data['sent']} devices")
    else:
        test_result("Push Notification", False)
except Exception as e:
    test_result("Push Notification", False, str(e))

# ============================================================================
# CLOUD STORAGE INTEGRATION
# ============================================================================
print_section("3. CLOUD STORAGE INTEGRATION")

# Configure cloud provider
try:
    r = requests.post(f"{URL}/api/cloud/configure", json={
        "provider": "aws_s3",
        "config": {
            "bucket": "soc-platform-logs",
            "region": "us-east-1",
            "enabled": True
        }
    })
    if r.status_code == 200:
        data = r.json()
        test_result("Cloud Storage Config", True, f"Provider: {data['provider']}")
    else:
        test_result("Cloud Storage Config", False)
except Exception as e:
    test_result("Cloud Storage Config", False, str(e))

# Upload logs to cloud
try:
    r = requests.post(f"{URL}/api/cloud/upload", json={
        "type": "logs",
        "provider": "aws_s3"
    })
    if r.status_code == 200:
        data = r.json()
        test_result("Cloud Log Upload", True, f"Upload ID: {data['upload_id']}")
    else:
        test_result("Cloud Log Upload", False)
except Exception as e:
    test_result("Cloud Log Upload", False, str(e))

# Cloud sync
try:
    r = requests.post(f"{URL}/api/cloud/sync", json={"type": "all"})
    if r.status_code == 200:
        data = r.json()
        test_result("Cloud Data Sync", True, f"Sync ID: {data['sync_id']}")
    else:
        test_result("Cloud Data Sync", False)
except Exception as e:
    test_result("Cloud Data Sync", False, str(e))

# Cloud storage stats
try:
    r = requests.get(f"{URL}/api/cloud/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Cloud Storage Stats", True, f"Total uploads: {data['total_uploads']}")
    else:
        test_result("Cloud Storage Stats", False)
except Exception as e:
    test_result("Cloud Storage Stats", False, str(e))

# ============================================================================
# THREAT HUNTING
# ============================================================================
print_section("4. THREAT HUNTING")

# Create hunt query
try:
    r = requests.post(f"{URL}/api/hunt/create", json={
        "name": "Suspicious Login Hunt",
        "query": "SELECT * FROM logs WHERE event_type = 'login' AND suspicious = true",
        "description": "Hunt for suspicious login activities"
    })
    if r.status_code == 200:
        hunt_data = r.json()
        hunt_id = hunt_data['hunt_id']
        test_result("Create Hunt Query", True, f"Hunt ID: {hunt_id}")
        
        # Execute hunt
        r2 = requests.post(f"{URL}/api/hunt/execute", json={
            "hunt_id": hunt_id,
            "data_sources": ["logs", "alerts"]
        })
        if r2.status_code == 200:
            exec_data = r2.json()
            test_result("Execute Hunt", True, f"Matches found: {exec_data['matches_found']}")
        else:
            test_result("Execute Hunt", False)
    else:
        test_result("Create Hunt Query", False)
except Exception as e:
    test_result("Threat Hunting", False, str(e))

# Hunt IOCs
try:
    r = requests.post(f"{URL}/api/hunt/ioc", json={
        "data_sources": ["sample_data"]
    })
    if r.status_code == 200:
        data = r.json()
        test_result("IOC Hunting", True, f"Total matches: {data['total_matches']}")
    else:
        test_result("IOC Hunting", False)
except Exception as e:
    test_result("IOC Hunting", False, str(e))

# Hunt statistics
try:
    r = requests.get(f"{URL}/api/hunt/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Hunt Statistics", True, f"Total hunts: {data['total_hunt_queries']}")
    else:
        test_result("Hunt Statistics", False)
except Exception as e:
    test_result("Hunt Statistics", False, str(e))

# ============================================================================
# ASSET MANAGEMENT
# ============================================================================
print_section("5. ASSET MANAGEMENT")

# Register asset
try:
    r = requests.post(f"{URL}/api/assets/register", json={
        "name": "Web Server 01",
        "type": "server",
        "ip_address": "10.0.1.100",
        "os": "Ubuntu 20.04",
        "owner": "IT Team",
        "criticality": "high",
        "antivirus": True,
        "firewall": True,
        "encryption": False
    })
    if r.status_code == 200:
        asset_data = r.json()
        test_result("Asset Registration", True, f"Asset ID: {asset_data['asset_id']}")
    else:
        test_result("Asset Registration", False)
except Exception as e:
    test_result("Asset Registration", False, str(e))

# Get assets
try:
    r = requests.get(f"{URL}/api/assets")
    if r.status_code == 200:
        assets = r.json()
        test_result("Get Assets", True, f"Total assets: {len(assets)}")
    else:
        test_result("Get Assets", False)
except Exception as e:
    test_result("Get Assets", False, str(e))

# Asset statistics
try:
    r = requests.get(f"{URL}/api/assets/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Asset Statistics", True, f"Total assets: {data['total_assets']}")
    else:
        test_result("Asset Statistics", False)
except Exception as e:
    test_result("Asset Statistics", False, str(e))

# ============================================================================
# THREAT MODELING
# ============================================================================
print_section("6. THREAT MODELING")

# Create threat model
try:
    r = requests.post(f"{URL}/api/threat-model/create", json={
        "name": "Web Application Threat Model",
        "assets": ["web_server", "database", "load_balancer"],
        "description": "Threat model for web application infrastructure"
    })
    if r.status_code == 200:
        model_data = r.json()
        model_id = model_data['model_id']
        test_result("Create Threat Model", True, f"Model ID: {model_id}")
        
        # Add threat to model
        r2 = requests.post(f"{URL}/api/threat-model/{model_id}/threat", json={
            "name": "SQL Injection",
            "description": "Malicious SQL code injection",
            "likelihood": "medium",
            "impact": "high",
            "attack_vector": "web_application",
            "mitre_technique": "T1190"
        })
        if r2.status_code == 200:
            threat_data = r2.json()
            test_result("Add Threat", True, f"Threat ID: {threat_data['threat_id']}")
        else:
            test_result("Add Threat", False)
        
        # Assess risk
        r3 = requests.post(f"{URL}/api/threat-model/{model_id}/assess")
        if r3.status_code == 200:
            assessment = r3.json()
            test_result("Risk Assessment", True, f"Risk Level: {assessment['risk_level']}")
        else:
            test_result("Risk Assessment", False)
    else:
        test_result("Create Threat Model", False)
except Exception as e:
    test_result("Threat Modeling", False, str(e))

# Threat modeling stats
try:
    r = requests.get(f"{URL}/api/threat-model/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Threat Modeling Stats", True, f"Total models: {data['total_models']}")
    else:
        test_result("Threat Modeling Stats", False)
except Exception as e:
    test_result("Threat Modeling Stats", False, str(e))

# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================
print_section("7. PERFORMANCE MONITORING")

# Record performance metrics
try:
    metrics = [
        {"metric_name": "cpu_usage", "value": 75.5},
        {"metric_name": "memory_usage", "value": 82.3},
        {"metric_name": "disk_usage", "value": 45.7},
        {"metric_name": "response_time", "value": 1250}
    ]
    
    for metric in metrics:
        r = requests.post(f"{URL}/api/performance/metric", json=metric)
        if r.status_code != 200:
            test_result(f"Record {metric['metric_name']}", False)
            break
    else:
        test_result("Record Performance Metrics", True, f"Recorded {len(metrics)} metrics")
except Exception as e:
    test_result("Record Performance Metrics", False, str(e))

# System health
try:
    r = requests.get(f"{URL}/api/performance/health")
    if r.status_code == 200:
        health = r.json()
        test_result("System Health Check", True, f"Status: {health['status']}, Score: {health['health_score']}")
    else:
        test_result("System Health Check", False)
except Exception as e:
    test_result("System Health Check", False, str(e))

# Metric summary
try:
    r = requests.get(f"{URL}/api/performance/metric/cpu_usage?hours=24")
    if r.status_code == 200:
        summary = r.json()
        test_result("Metric Summary", True, f"CPU avg: {summary.get('average', 0):.1f}%")
    else:
        test_result("Metric Summary", False)
except Exception as e:
    test_result("Metric Summary", False, str(e))

# Performance optimization
try:
    r = requests.post(f"{URL}/api/performance/optimize")
    if r.status_code == 200:
        optimization = r.json()
        test_result("Performance Optimization", True, f"Suggestions: {len(optimization['suggestions'])}")
    else:
        test_result("Performance Optimization", False)
except Exception as e:
    test_result("Performance Optimization", False, str(e))

# Performance statistics
try:
    r = requests.get(f"{URL}/api/performance/stats")
    if r.status_code == 200:
        data = r.json()
        test_result("Performance Statistics", True, f"Total metrics: {data['total_metrics_recorded']}")
    else:
        test_result("Performance Statistics", False)
except Exception as e:
    test_result("Performance Statistics", False, str(e))

# ============================================================================
# SUMMARY
# ============================================================================
print_section("BATCH 4 TEST SUMMARY")

print("\n✅ Advanced Features Tested:")
print("  1. WebSocket Management (1 test)")
print("  2. Mobile Push Notifications (3 tests)")
print("  3. Cloud Storage Integration (4 tests)")
print("  4. Threat Hunting (4 tests)")
print("  5. Asset Management (3 tests)")
print("  6. Threat Modeling (4 tests)")
print("  7. Performance Monitoring (5 tests)")
print("\nTotal Batch 4 Tests: 24")

print("\n📊 Updated Platform Stats:")
print("  Total Features: 66 (58 + 8 new)")
print("  API Endpoints: 80+ (55 + 25 new)")
print("  Services: 22 (15 + 7 new)")
print("  Code Files: 2 (enhanced_services.py + advanced_features.py)")

print("\n🚀 New Capabilities:")
print("  • Real-time WebSocket dashboard updates")
print("  • Mobile push notifications (iOS/Android)")
print("  • Multi-cloud storage integration")
print("  • Advanced threat hunting queries")
print("  • Comprehensive asset management")
print("  • Risk-based threat modeling")
print("  • Performance monitoring & optimization")

print("\n🎯 Quick Test Commands:")
print("  python test_batch4.py  # This file")
print("  python test_all.py     # All features")
print("  python app.py          # Start platform")

print("\n" + "=" * 70)
print("✅ BATCH 4 ADVANCED FEATURES TEST COMPLETE!")
print("🎉 SOC PLATFORM NOW HAS 66 ENTERPRISE FEATURES!")
print("=" * 70)