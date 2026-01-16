from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from web.config.settings import Config
from core.normalization.normalizer import LogNormalizer
from core.correlation.engine import CorrelationEngine
from core.alert_manager.manager import AlertManager
from core.ml_detection.anomaly_detector import AnomalyDetector
from core.incident_response.responder import IncidentResponder
from core.threat_intel.intelligence import ThreatIntelligence
from core.soar.playbook_engine import PlaybookEngine
from core.analytics.behavioral import BehavioralAnalytics
from core.forensics.investigation import ForensicsEngine
from core.compliance.reporter import ComplianceReporter
from core.enhanced_services import (
    NotificationManager, GeoLocationService, ExportService,
    SearchEngine, ThreatFeedService, ThemeManager, AlertSoundManager,
    AuthenticationManager, ReportGenerator, VulnerabilityScanner, NetworkMonitor,
    ThreatPredictor, BackupManager, RateLimiter, AuditLogger
)
from datetime import datetime
import json

app = Flask(__name__, template_folder='web/templates', static_folder='web/static')
app.config.from_object(Config)
CORS(app)

# Initialize components
config = Config()
normalizer = LogNormalizer()
correlation_engine = CorrelationEngine(config)
alert_manager = AlertManager(config)
anomaly_detector = AnomalyDetector(config)
incident_responder = IncidentResponder(config)
threat_intel = ThreatIntelligence(config)
playbook_engine = PlaybookEngine()
behavioral_analytics = BehavioralAnalytics()
forensics_engine = ForensicsEngine()
compliance_reporter = ComplianceReporter()

# Enhanced services
notification_manager = NotificationManager()
geo_service = GeoLocationService()
export_service = ExportService()
search_engine = SearchEngine()
threat_feed = ThreatFeedService()
theme_manager = ThemeManager()
alert_sound = AlertSoundManager()
auth_manager = AuthenticationManager()
report_generator = ReportGenerator()
vuln_scanner = VulnerabilityScanner()
network_monitor = NetworkMonitor()
threat_predictor = ThreatPredictor()
backup_manager = BackupManager()
rate_limiter = RateLimiter()
audit_logger = AuditLogger()

# In-memory log storage with persistence
logs_storage = []

def load_logs_from_file():
    """Load logs from file on startup"""
    global logs_storage
    try:
        if os.path.exists('data/logs/stored_logs.json'):
            with open('data/logs/stored_logs.json', 'r') as f:
                logs_storage = json.load(f)
                print(f"✓ Loaded {len(logs_storage)} logs from storage")
    except Exception as e:
        print(f"Warning: Could not load logs: {e}")
        logs_storage = []

def save_logs_to_file():
    """Save logs to file"""
    try:
        os.makedirs('data/logs', exist_ok=True)
        with open('data/logs/stored_logs.json', 'w') as f:
            json.dump(logs_storage[-1000:], f)  # Keep last 1000 logs
    except Exception as e:
        print(f"Warning: Could not save logs: {e}")

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/ingest', methods=['POST'])
def ingest_log():
    data = request.json
    log_type = data.get('log_type', 'json')
    log_entry = data.get('log')
    
    # Normalize
    normalized = normalizer.normalize(log_entry, log_type)
    logs_storage.append(normalized)
    
    # Save to file every 10 logs
    if len(logs_storage) % 10 == 0:
        save_logs_to_file()
    
    # Correlate
    alerts = correlation_engine.analyze(normalized)
    
    # Create alerts
    for alert_data in alerts:
        alert = alert_manager.create_alert(alert_data)
        if alert:
            # Add to geolocation map
            if alert.get('source_ip'):
                geo_service.add_attack(alert['source_ip'], alert)
            
            # Send notifications
            notification_manager.send_alert(alert)
            
            # Auto-respond
            incident_responder.handle_alert(alert, alert_manager)
    
    return jsonify({'status': 'success', 'alerts_generated': len(alerts)})

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    status = request.args.get('status')
    severity = request.args.get('severity')
    alerts = alert_manager.get_alerts(status, severity)
    return jsonify(alerts)

@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    status = request.args.get('status')
    incidents = incident_responder.get_incidents(status)
    return jsonify(incidents)

@app.route('/api/logs', methods=['GET'])
def get_logs():
    limit = int(request.args.get('limit', 100))
    return jsonify(logs_storage[-limit:])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    alerts = alert_manager.get_alerts()
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for alert in alerts:
        severity_counts[alert['severity']] = severity_counts.get(alert['severity'], 0) + 1
    
    stats = {
        'total_logs': len(logs_storage),
        'total_alerts': len(alerts),
        'active_incidents': len([i for i in incident_responder.incidents if i['status'] == 'INVESTIGATING']),
        'severity_distribution': severity_counts,
        'top_attackers': get_top_attackers(alerts),
        'mitre_techniques': get_mitre_distribution(alerts)
    }
    return jsonify(stats)

@app.route('/api/anomalies', methods=['POST'])
def detect_anomalies():
    recent_logs = logs_storage[-100:]
    anomalies = anomaly_detector.detect_anomalies(recent_logs)
    
    for anomaly in anomalies:
        alert_manager.create_alert(anomaly)
    
    return jsonify({'anomalies_detected': len(anomalies), 'anomalies': anomalies})

@app.route('/api/threat-intel/<ip>', methods=['GET'])
def get_threat_intel(ip):
    report = threat_intel.get_threat_report(ip)
    return jsonify(report)

@app.route('/api/playbooks', methods=['GET'])
def list_playbooks():
    playbooks = playbook_engine.list_playbooks()
    return jsonify(playbooks)

@app.route('/api/playbooks/execute', methods=['POST'])
def execute_playbook():
    data = request.json
    playbook_name = data.get('playbook_name')
    context = data.get('context', {})
    result = playbook_engine.execute_playbook(playbook_name, context)
    return jsonify(result)

@app.route('/api/forensics/investigate', methods=['POST'])
def start_investigation():
    data = request.json
    investigation = forensics_engine.start_investigation(
        data.get('alert_id'),
        data.get('incident_id')
    )
    return jsonify(investigation)

@app.route('/api/forensics/evidence', methods=['POST'])
def collect_evidence():
    data = request.json
    evidence = forensics_engine.collect_evidence(
        data.get('investigation_id'),
        data.get('evidence_type'),
        data.get('data')
    )
    return jsonify(evidence)

@app.route('/api/compliance/report', methods=['GET'])
def compliance_report():
    framework = request.args.get('framework', 'ISO27001')
    alerts = alert_manager.get_alerts()
    incidents = incident_responder.get_incidents()
    report = compliance_reporter.generate_compliance_report(framework, alerts, incidents)
    return jsonify(report)

@app.route('/api/behavioral/risk/<user>', methods=['GET'])
def user_risk_score(user):
    score = behavioral_analytics.get_user_risk_score(user)
    return jsonify({'user': user, 'risk_score': score})

@app.route('/api/geolocation/attacks', methods=['GET'])
def get_attack_map():
    attacks = geo_service.get_attack_map()
    return jsonify(attacks)

@app.route('/api/geolocation/stats', methods=['GET'])
def get_geo_stats():
    stats = geo_service.get_country_stats()
    return jsonify(stats)

@app.route('/api/export/alerts', methods=['GET'])
def export_alerts():
    alerts = alert_manager.get_alerts()
    csv_data = export_service.export_to_csv(alerts, 'alerts')
    return app.response_class(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=alerts.csv'})

@app.route('/api/export/incidents', methods=['GET'])
def export_incidents():
    incidents = incident_responder.get_incidents()
    csv_data = export_service.export_to_csv(incidents, 'incidents')
    return app.response_class(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=incidents.csv'})

@app.route('/api/export/logs', methods=['GET'])
def export_logs():
    csv_data = export_service.export_to_csv(logs_storage, 'logs')
    return app.response_class(csv_data, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=logs.csv'})

@app.route('/api/notifications/configure', methods=['POST'])
def configure_notifications():
    data = request.json
    if data.get('type') == 'email':
        notification_manager.configure_email(data.get('from_email'), data.get('recipients'))
        return jsonify({'status': 'configured', 'type': 'email'})
    elif data.get('type') == 'slack':
        notification_manager.configure_slack(data.get('webhook_url'))
        return jsonify({'status': 'configured', 'type': 'slack'})
    return jsonify({'error': 'Invalid type'})

@app.route('/api/search', methods=['POST'])
def search_data():
    data = request.json
    query = data.get('query', '')
    data_type = data.get('type', 'alerts')
    
    if data_type == 'alerts':
        results = search_engine.search(alert_manager.get_alerts(), query)
    elif data_type == 'incidents':
        results = search_engine.search(incident_responder.get_incidents(), query)
    else:
        results = search_engine.search(logs_storage, query)
    
    return jsonify(results)

@app.route('/api/threat-feed/<ip>', methods=['GET'])
def check_threat_feed(ip):
    report = threat_feed.get_comprehensive_report(ip)
    return jsonify(report)

@app.route('/api/theme', methods=['GET', 'POST'])
def manage_theme():
    if request.method == 'POST':
        theme_name = request.json.get('theme')
        theme = theme_manager.set_theme(theme_name)
        return jsonify({'theme': theme_name, 'colors': theme})
    return jsonify({'current': theme_manager.current_theme, 'available': theme_manager.list_themes()})

@app.route('/api/alert-sound/toggle', methods=['POST'])
def toggle_alert_sound():
    enabled = alert_sound.toggle()
    return jsonify({'enabled': enabled})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    ip = request.remote_addr
    
    # Check rate limit
    rate_check = rate_limiter.check_rate_limit(ip, 'auth')
    if not rate_check['allowed']:
        return jsonify({'error': 'Rate limit exceeded', 'retry_after': rate_check.get('retry_after')}), 429
    
    result = auth_manager.login(data.get('username'), data.get('password'))
    
    # Log attempt
    audit_logger.log_login(data.get('username'), ip, result is not None)
    
    if result:
        return jsonify(result)
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    auth_manager.logout(token)
    return jsonify({'status': 'logged out'})

@app.route('/api/auth/verify', methods=['GET'])
def verify_token():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    session = auth_manager.verify_token(token)
    if session:
        return jsonify(session)
    return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/reports/executive', methods=['GET'])
def executive_report():
    alerts = alert_manager.get_alerts()
    incidents = incident_responder.get_incidents()
    report = report_generator.generate_executive_summary(alerts, incidents)
    return jsonify(report)

@app.route('/api/reports/incident/<incident_id>', methods=['GET'])
def incident_report(incident_id):
    incidents = incident_responder.get_incidents()
    incident = next((i for i in incidents if i['incident_id'] == incident_id), None)
    if incident:
        report = report_generator.generate_incident_report(incident)
        return jsonify(report)
    return jsonify({'error': 'Incident not found'}), 404

@app.route('/api/vulnerability/scan', methods=['POST'])
def scan_vulnerability():
    data = request.json
    target = data.get('target', '192.168.1.1')
    scan_result = vuln_scanner.scan_system(target)
    return jsonify(scan_result)

@app.route('/api/vulnerability/history', methods=['GET'])
def vulnerability_history():
    history = vuln_scanner.get_scan_history()
    return jsonify(history)

@app.route('/api/vulnerability/summary', methods=['GET'])
def vulnerability_summary():
    summary = vuln_scanner.get_vulnerability_summary()
    return jsonify(summary)

@app.route('/api/network/connections', methods=['GET'])
def network_connections():
    connections = network_monitor.get_active_connections()
    return jsonify(connections)

@app.route('/api/network/block', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Security threat')
    result = network_monitor.block_ip(ip, reason)
    return jsonify(result)

@app.route('/api/network/unblock', methods=['POST'])
def unblock_ip():
    data = request.json
    ip = data.get('ip')
    result = network_monitor.unblock_ip(ip)
    return jsonify(result)

@app.route('/api/network/stats', methods=['GET'])
def network_stats():
    stats = network_monitor.get_connection_stats()
    return jsonify(stats)

@app.route('/api/network/blocked', methods=['GET'])
def blocked_ips():
    blocked = network_monitor.get_blocked_ips()
    return jsonify({'blocked_ips': blocked})

@app.route('/api/ml/predict', methods=['POST'])
def predict_threat():
    data = request.json
    prediction = threat_predictor.predict_threat(data)
    return jsonify(prediction)

@app.route('/api/ml/predict-next-attack', methods=['POST'])
def predict_next_attack():
    alerts = alert_manager.get_alerts()
    prediction = threat_predictor.predict_next_attack(alerts)
    return jsonify(prediction)

@app.route('/api/ml/trends', methods=['GET'])
def threat_trends():
    alerts = alert_manager.get_alerts()
    trends = threat_predictor.analyze_threat_trends(alerts)
    return jsonify(trends)

@app.route('/api/backup/create', methods=['POST'])
def create_backup():
    data = request.json
    data_type = data.get('type', 'alerts')
    if data_type == 'alerts':
        backup_data = alert_manager.get_alerts()
    elif data_type == 'incidents':
        backup_data = incident_responder.get_incidents()
    else:
        backup_data = logs_storage
    backup = backup_manager.create_backup(data_type, backup_data)
    return jsonify(backup)

@app.route('/api/backup/list', methods=['GET'])
def list_backups():
    backups = backup_manager.list_backups()
    return jsonify(backups)

@app.route('/api/backup/restore/<backup_id>', methods=['POST'])
def restore_backup(backup_id):
    result = backup_manager.restore_backup(backup_id)
    return jsonify(result)

@app.route('/api/backup/stats', methods=['GET'])
def backup_stats():
    stats = backup_manager.get_backup_stats()
    return jsonify(stats)

@app.route('/api/audit/logs', methods=['GET'])
def get_audit_logs():
    user = request.args.get('user')
    level = request.args.get('level')
    logs = audit_logger.get_logs(user, level)
    return jsonify(logs)

@app.route('/api/audit/user/<username>', methods=['GET'])
def user_activity(username):
    activity = audit_logger.get_user_activity(username)
    return jsonify(activity)

@app.route('/api/audit/export', methods=['GET'])
def export_audit():
    trail = audit_logger.export_audit_trail()
    return jsonify(trail)

@app.route('/api/rate-limit/stats', methods=['GET'])
def rate_limit_stats():
    stats = rate_limiter.get_stats()
    return jsonify(stats)

def get_top_attackers(alerts, limit=5):
    ip_counts = {}
    for alert in alerts:
        ip = alert.get('source_ip')
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return [{'ip': ip, 'count': count} for ip, count in sorted_ips[:limit]]

def get_mitre_distribution(alerts):
    mitre_counts = {}
    for alert in alerts:
        mitre = alert.get('mitre_attack', 'Unknown')
        mitre_counts[mitre] = mitre_counts.get(mitre, 0) + 1
    return mitre_counts

if __name__ == '__main__':
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.LOGS_DIR, exist_ok=True)
    
    # Load existing logs on startup
    load_logs_from_file()
    
    app.run(debug=True, host='0.0.0.0', port=5000)
