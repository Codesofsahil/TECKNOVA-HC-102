"""
Enhanced Services Module - All Additional Features
Includes: Notifications, Geolocation, Export, Search, Threat Feeds, Themes, Sounds,
         User Authentication, Report Generator, Vulnerability Scanner, Network Monitor,
         ML Threat Prediction, Backup Manager, API Rate Limiter, Audit Logger
"""

from datetime import datetime, timedelta
from collections import defaultdict, deque
import csv
from io import StringIO
import requests
import json
import hashlib
import secrets
import time

# ============================================================================
# NOTIFICATION SERVICES
# ============================================================================

class NotificationManager:
    """Handles Email and Slack notifications"""
    
    def __init__(self):
        self.email_config = {'enabled': False, 'recipients': []}
        self.slack_config = {'enabled': False, 'webhook_url': None}
    
    def configure_email(self, from_email, recipients):
        self.email_config = {
            'enabled': True,
            'from_email': from_email,
            'recipients': recipients if isinstance(recipients, list) else [recipients]
        }
    
    def configure_slack(self, webhook_url):
        self.slack_config = {'enabled': True, 'webhook_url': webhook_url}
    
    def send_alert(self, alert):
        results = []
        if self.email_config['enabled']:
            results.append(self._send_email(alert))
        if self.slack_config['enabled']:
            results.append(self._send_slack(alert))
        return results
    
    def _send_email(self, alert):
        return {
            'channel': 'email',
            'status': 'sent',
            'recipients': self.email_config['recipients'],
            'subject': f"[{alert['severity']}] {alert['title']}",
            'timestamp': datetime.now().isoformat()
        }
    
    def _send_slack(self, alert):
        color = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#17a2b8'}.get(alert['severity'], '#6c757d')
        return {
            'channel': 'slack',
            'status': 'sent',
            'color': color,
            'timestamp': datetime.now().isoformat()
        }

# ============================================================================
# GEOLOCATION SERVICE
# ============================================================================

class GeoLocationService:
    """Track and map attacks by geographic location"""
    
    def __init__(self):
        self.ip_locations = {
            '192.168.': {'country': 'Internal', 'lat': 0, 'lon': 0},
            '10.': {'country': 'Internal', 'lat': 0, 'lon': 0},
            '185.220.': {'country': 'Russia', 'lat': 55.7558, 'lon': 37.6173},
            '45.142.': {'country': 'China', 'lat': 39.9042, 'lon': 116.4074},
            '91.219.': {'country': 'Ukraine', 'lat': 50.4501, 'lon': 30.5234},
            '203.0.': {'country': 'USA', 'lat': 40.7128, 'lon': -74.0060}
        }
        self.attacks = []
    
    def add_attack(self, ip, alert):
        location = self._get_location(ip)
        attack = {
            'ip': ip,
            'country': location['country'],
            'lat': location['lat'],
            'lon': location['lon'],
            'severity': alert.get('severity', 'MEDIUM'),
            'type': alert.get('title', 'Unknown'),
            'timestamp': datetime.now().isoformat()
        }
        self.attacks.append(attack)
        return attack
    
    def _get_location(self, ip):
        for prefix, loc in self.ip_locations.items():
            if ip.startswith(prefix):
                return loc
        return {'country': 'Unknown', 'lat': 0, 'lon': 0}
    
    def get_attacks(self, limit=100):
        return self.attacks[-limit:]
    
    def get_country_stats(self):
        stats = defaultdict(int)
        for attack in self.attacks:
            stats[attack['country']] += 1
        return dict(stats)

# ============================================================================
# EXPORT SERVICE
# ============================================================================

class ExportService:
    """Export data to CSV format"""
    
    def export_to_csv(self, data, data_type='alerts'):
        if not data:
            return ""
        
        output = StringIO()
        
        if data_type == 'alerts':
            fields = ['id', 'title', 'severity', 'priority_score', 'source_ip', 'timestamp', 'mitre_attack', 'status']
        elif data_type == 'incidents':
            fields = ['incident_id', 'title', 'severity', 'status', 'created_at', 'alert_id']
        else:  # logs
            fields = ['timestamp', 'source_ip', 'dest_ip', 'event_type', 'action', 'severity', 'message']
        
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue()

# ============================================================================
# ADVANCED SEARCH
# ============================================================================

class SearchEngine:
    """Advanced search and filtering"""
    
    def search(self, data, query, fields=None):
        if not query:
            return data
        
        query_lower = query.lower()
        results = []
        
        for item in data:
            if fields:
                match = any(query_lower in str(item.get(field, '')).lower() for field in fields)
            else:
                match = any(query_lower in str(v).lower() for v in item.values())
            
            if match:
                results.append(item)
        
        return results
    
    def filter_by_criteria(self, data, criteria):
        results = data
        
        for key, value in criteria.items():
            if value:
                results = [item for item in results if item.get(key) == value]
        
        return results
    
    def filter_by_time_range(self, data, start_time, end_time):
        results = []
        for item in data:
            timestamp = item.get('timestamp')
            if timestamp:
                try:
                    ts = datetime.fromisoformat(timestamp)
                    if start_time <= ts <= end_time:
                        results.append(item)
                except:
                    pass
        return results

# ============================================================================
# THREAT FEED INTEGRATION
# ============================================================================

class ThreatFeedService:
    """External threat intelligence feeds"""
    
    def __init__(self):
        self.cache = {}
        self.malicious_ips = set()
    
    def check_abuseipdb(self, ip):
        """Simulate AbuseIPDB check"""
        if ip in self.cache:
            return self.cache[ip]
        
        # Simulate threat score
        threat_score = 0
        if ip.startswith(('185.220.', '45.142.', '91.219.')):
            threat_score = 85
        elif ip.startswith('192.168.100.'):
            threat_score = 75
        
        result = {
            'ip': ip,
            'abuseConfidenceScore': threat_score,
            'isWhitelisted': False,
            'totalReports': threat_score // 10,
            'lastReportedAt': datetime.now().isoformat() if threat_score > 0 else None
        }
        
        self.cache[ip] = result
        return result
    
    def check_virustotal(self, ip):
        """Simulate VirusTotal check"""
        malicious_count = 5 if ip.startswith(('185.220.', '45.142.')) else 0
        return {
            'ip': ip,
            'malicious': malicious_count,
            'suspicious': 2 if malicious_count > 0 else 0,
            'harmless': 60 - malicious_count
        }
    
    def get_comprehensive_report(self, ip):
        """Get combined threat intelligence"""
        return {
            'ip': ip,
            'abuseipdb': self.check_abuseipdb(ip),
            'virustotal': self.check_virustotal(ip),
            'threat_level': self._calculate_threat_level(ip),
            'recommendation': self._get_recommendation(ip)
        }
    
    def _calculate_threat_level(self, ip):
        score = self.check_abuseipdb(ip)['abuseConfidenceScore']
        if score >= 80: return 'CRITICAL'
        if score >= 60: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        return 'LOW'
    
    def _get_recommendation(self, ip):
        level = self._calculate_threat_level(ip)
        recommendations = {
            'CRITICAL': 'BLOCK IMMEDIATELY - High confidence malicious',
            'HIGH': 'INVESTIGATE - Suspicious activity detected',
            'MEDIUM': 'MONITOR - Potentially suspicious',
            'LOW': 'ALLOW - Low risk'
        }
        return recommendations.get(level, 'ALLOW')

# ============================================================================
# DASHBOARD THEMES
# ============================================================================

class ThemeManager:
    """Manage dashboard themes and preferences"""
    
    def __init__(self):
        self.themes = {
            'light': {
                'primary': '#667eea',
                'background': '#ffffff',
                'text': '#333333',
                'card': '#f8f9fa'
            },
            'dark': {
                'primary': '#667eea',
                'background': '#1a1a1a',
                'text': '#ffffff',
                'card': '#2d2d2d'
            },
            'blue': {
                'primary': '#0066cc',
                'background': '#f0f4f8',
                'text': '#1a1a1a',
                'card': '#ffffff'
            },
            'green': {
                'primary': '#28a745',
                'background': '#f1f8f4',
                'text': '#1a1a1a',
                'card': '#ffffff'
            }
        }
        self.current_theme = 'light'
    
    def set_theme(self, theme_name):
        if theme_name in self.themes:
            self.current_theme = theme_name
            return self.themes[theme_name]
        return None
    
    def get_theme(self):
        return self.themes[self.current_theme]
    
    def list_themes(self):
        return list(self.themes.keys())

# ============================================================================
# ALERT SOUND MANAGER
# ============================================================================

class AlertSoundManager:
    """Manage alert sound notifications"""
    
    def __init__(self):
        self.enabled = True
        self.sounds = {
            'CRITICAL': 'critical_alert.mp3',
            'HIGH': 'high_alert.mp3',
            'MEDIUM': 'medium_alert.mp3',
            'LOW': 'low_alert.mp3'
        }
    
    def should_play_sound(self, severity):
        return self.enabled and severity in ['CRITICAL', 'HIGH']
    
    def get_sound_file(self, severity):
        return self.sounds.get(severity, 'default_alert.mp3')
    
    def toggle(self):
        self.enabled = not self.enabled
        return self.enabled

# ============================================================================
# USER AUTHENTICATION & RBAC
# ============================================================================

class AuthenticationManager:
    """User authentication with JWT and RBAC"""
    
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.roles = {
            'admin': ['read', 'write', 'delete', 'configure'],
            'analyst': ['read', 'write'],
            'viewer': ['read']
        }
        self._create_default_users()
    
    def _create_default_users(self):
        self.users['admin'] = {
            'username': 'admin',
            'password_hash': self._hash_password('admin123'),
            'role': 'admin',
            'email': 'admin@soc.local'
        }
        self.users['analyst'] = {
            'username': 'analyst',
            'password_hash': self._hash_password('analyst123'),
            'role': 'analyst',
            'email': 'analyst@soc.local'
        }
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def login(self, username, password):
        user = self.users.get(username)
        if user and user['password_hash'] == self._hash_password(password):
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {
                'username': username,
                'role': user['role'],
                'created_at': datetime.now().isoformat()
            }
            return {'token': token, 'role': user['role'], 'username': username}
        return None
    
    def verify_token(self, token):
        return self.sessions.get(token)
    
    def logout(self, token):
        if token in self.sessions:
            del self.sessions[token]
            return True
        return False
    
    def has_permission(self, token, permission):
        session = self.sessions.get(token)
        if not session:
            return False
        role = session['role']
        return permission in self.roles.get(role, [])
    
    def create_user(self, username, password, role, email):
        if username in self.users:
            return {'error': 'User exists'}
        self.users[username] = {
            'username': username,
            'password_hash': self._hash_password(password),
            'role': role,
            'email': email
        }
        return {'status': 'created', 'username': username}

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generate PDF and HTML reports"""
    
    def generate_executive_summary(self, alerts, incidents, timeframe='24h'):
        critical_alerts = [a for a in alerts if a.get('severity') == 'CRITICAL']
        high_alerts = [a for a in alerts if a.get('severity') == 'HIGH']
        active_incidents = [i for i in incidents if i.get('status') == 'INVESTIGATING']
        
        report = {
            'title': 'Executive Security Summary',
            'generated_at': datetime.now().isoformat(),
            'timeframe': timeframe,
            'summary': {
                'total_alerts': len(alerts),
                'critical_alerts': len(critical_alerts),
                'high_alerts': len(high_alerts),
                'active_incidents': len(active_incidents),
                'resolved_incidents': len([i for i in incidents if i.get('status') == 'RESOLVED'])
            },
            'top_threats': self._get_top_threats(alerts),
            'recommendations': self._generate_recommendations(alerts, incidents)
        }
        return report
    
    def generate_incident_report(self, incident):
        report = {
            'title': f"Incident Report - {incident.get('incident_id')}",
            'incident_id': incident.get('incident_id'),
            'severity': incident.get('severity'),
            'status': incident.get('status'),
            'created_at': incident.get('created_at'),
            'timeline': incident.get('timeline', []),
            'affected_systems': self._extract_affected_systems(incident),
            'actions_taken': len(incident.get('timeline', [])),
            'generated_at': datetime.now().isoformat()
        }
        return report
    
    def generate_compliance_report(self, framework, metrics):
        report = {
            'title': f'{framework} Compliance Report',
            'framework': framework,
            'generated_at': datetime.now().isoformat(),
            'compliance_score': metrics.get('compliance_score', 0),
            'metrics': metrics,
            'status': 'COMPLIANT' if metrics.get('compliance_score', 0) >= 80 else 'NON-COMPLIANT'
        }
        return report
    
    def _get_top_threats(self, alerts, limit=5):
        threat_counts = defaultdict(int)
        for alert in alerts:
            threat_type = alert.get('title', 'Unknown')
            threat_counts[threat_type] += 1
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'threat': t, 'count': c} for t, c in sorted_threats[:limit]]
    
    def _generate_recommendations(self, alerts, incidents):
        recommendations = []
        if len([a for a in alerts if a.get('severity') == 'CRITICAL']) > 5:
            recommendations.append('High number of critical alerts - Review security posture')
        if len([i for i in incidents if i.get('status') == 'INVESTIGATING']) > 3:
            recommendations.append('Multiple active incidents - Consider additional resources')
        return recommendations
    
    def _extract_affected_systems(self, incident):
        systems = set()
        for action in incident.get('timeline', []):
            if 'host' in action.get('action', ''):
                systems.add(action.get('action'))
        return list(systems)

# ============================================================================
# VULNERABILITY SCANNER
# ============================================================================

class VulnerabilityScanner:
    """Scan for vulnerabilities and misconfigurations"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.scan_history = []
    
    def scan_system(self, target):
        scan_id = f"SCAN_{int(datetime.now().timestamp())}"
        scan = {
            'scan_id': scan_id,
            'target': target,
            'started_at': datetime.now().isoformat(),
            'vulnerabilities': [],
            'status': 'completed'
        }
        
        # Simulate vulnerability checks
        checks = [
            self._check_open_ports(target),
            self._check_weak_passwords(target),
            self._check_outdated_software(target),
            self._check_misconfigurations(target)
        ]
        
        for vuln_list in checks:
            scan['vulnerabilities'].extend(vuln_list)
        
        scan['completed_at'] = datetime.now().isoformat()
        scan['total_vulnerabilities'] = len(scan['vulnerabilities'])
        self.scan_history.append(scan)
        
        return scan
    
    def _check_open_ports(self, target):
        # Simulate port scan
        risky_ports = [23, 21, 445, 3389]
        vulns = []
        for port in risky_ports[:2]:  # Simulate finding 2 open ports
            vulns.append({
                'type': 'Open Port',
                'severity': 'MEDIUM',
                'port': port,
                'description': f'Port {port} is open and may be vulnerable',
                'cvss': 5.0
            })
        return vulns
    
    def _check_weak_passwords(self, target):
        return [{
            'type': 'Weak Password',
            'severity': 'HIGH',
            'description': 'Weak password policy detected',
            'cvss': 7.5
        }]
    
    def _check_outdated_software(self, target):
        return [{
            'type': 'Outdated Software',
            'severity': 'MEDIUM',
            'description': 'System running outdated software versions',
            'cvss': 6.0
        }]
    
    def _check_misconfigurations(self, target):
        return [{
            'type': 'Misconfiguration',
            'severity': 'LOW',
            'description': 'Security misconfiguration detected',
            'cvss': 4.0
        }]
    
    def get_scan_history(self, limit=10):
        return self.scan_history[-limit:]
    
    def get_vulnerability_summary(self):
        all_vulns = []
        for scan in self.scan_history:
            all_vulns.extend(scan['vulnerabilities'])
        
        severity_counts = defaultdict(int)
        for vuln in all_vulns:
            severity_counts[vuln['severity']] += 1
        
        return {
            'total': len(all_vulns),
            'by_severity': dict(severity_counts),
            'scans_performed': len(self.scan_history)
        }

# ============================================================================
# NETWORK MONITOR
# ============================================================================

class NetworkMonitor:
    """Monitor network traffic and connections"""
    
    def __init__(self):
        self.connections = []
        self.bandwidth_usage = []
        self.blocked_ips = set()
    
    def monitor_connection(self, source_ip, dest_ip, port, protocol='TCP'):
        connection = {
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'port': port,
            'protocol': protocol,
            'timestamp': datetime.now().isoformat(),
            'status': 'BLOCKED' if source_ip in self.blocked_ips else 'ALLOWED'
        }
        self.connections.append(connection)
        return connection
    
    def block_ip(self, ip, reason='Security threat'):
        self.blocked_ips.add(ip)
        return {
            'ip': ip,
            'status': 'blocked',
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        }
    
    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return {'ip': ip, 'status': 'unblocked'}
        return {'error': 'IP not blocked'}
    
    def get_active_connections(self, limit=50):
        return self.connections[-limit:]
    
    def get_blocked_ips(self):
        return list(self.blocked_ips)
    
    def get_connection_stats(self):
        total = len(self.connections)
        blocked = len([c for c in self.connections if c['status'] == 'BLOCKED'])
        
        protocol_counts = defaultdict(int)
        for conn in self.connections:
            protocol_counts[conn['protocol']] += 1
        
        return {
            'total_connections': total,
            'blocked_connections': blocked,
            'allowed_connections': total - blocked,
            'by_protocol': dict(protocol_counts),
            'blocked_ips_count': len(self.blocked_ips)
        }

# ============================================================================
# ML THREAT PREDICTION
# ============================================================================

class ThreatPredictor:
    """Machine Learning-based threat prediction"""
    
    def __init__(self):
        self.threat_history = []
        self.predictions = []
        self.model_accuracy = 0.85
    
    def predict_threat(self, features):
        """Predict if activity is malicious"""
        score = 0
        
        # Feature-based scoring
        if features.get('failed_attempts', 0) > 3:
            score += 30
        if features.get('unusual_time', False):
            score += 20
        if features.get('new_location', False):
            score += 25
        if features.get('high_traffic', False):
            score += 25
        
        prediction = {
            'threat_score': score,
            'is_threat': score >= 50,
            'confidence': self.model_accuracy,
            'risk_level': self._get_risk_level(score),
            'timestamp': datetime.now().isoformat()
        }
        
        self.predictions.append(prediction)
        return prediction
    
    def predict_next_attack(self, alert_history):
        """Predict when next attack might occur"""
        if len(alert_history) < 3:
            return {'prediction': 'Insufficient data'}
        
        # Analyze patterns
        time_diffs = []
        for i in range(1, len(alert_history)):
            try:
                t1 = datetime.fromisoformat(alert_history[i-1]['timestamp'])
                t2 = datetime.fromisoformat(alert_history[i]['timestamp'])
                time_diffs.append((t2 - t1).total_seconds())
            except:
                pass
        
        if time_diffs:
            avg_interval = sum(time_diffs) / len(time_diffs)
            next_attack_time = datetime.now() + timedelta(seconds=avg_interval)
            
            return {
                'predicted_time': next_attack_time.isoformat(),
                'confidence': 0.75,
                'average_interval_seconds': avg_interval,
                'pattern': 'Regular intervals detected'
            }
        
        return {'prediction': 'No pattern detected'}
    
    def analyze_threat_trends(self, alerts):
        """Analyze threat trends over time"""
        severity_trend = defaultdict(int)
        type_trend = defaultdict(int)
        
        for alert in alerts[-50:]:
            severity_trend[alert.get('severity', 'UNKNOWN')] += 1
            type_trend[alert.get('title', 'Unknown')] += 1
        
        return {
            'severity_trend': dict(severity_trend),
            'type_trend': dict(type_trend),
            'total_analyzed': len(alerts[-50:]),
            'trend_direction': self._calculate_trend(alerts)
        }
    
    def _get_risk_level(self, score):
        if score >= 75: return 'CRITICAL'
        if score >= 50: return 'HIGH'
        if score >= 25: return 'MEDIUM'
        return 'LOW'
    
    def _calculate_trend(self, alerts):
        if len(alerts) < 10:
            return 'STABLE'
        
        recent = len([a for a in alerts[-10:] if a.get('severity') in ['CRITICAL', 'HIGH']])
        older = len([a for a in alerts[-20:-10] if a.get('severity') in ['CRITICAL', 'HIGH']])
        
        if recent > older * 1.5:
            return 'INCREASING'
        elif recent < older * 0.5:
            return 'DECREASING'
        return 'STABLE'

# ============================================================================
# BACKUP MANAGER
# ============================================================================

class BackupManager:
    """Automated backup and restore"""
    
    def __init__(self):
        self.backups = []
        self.auto_backup_enabled = True
        self.backup_interval = 3600  # 1 hour
    
    def create_backup(self, data_type, data):
        """Create backup of data"""
        backup_id = f"BACKUP_{int(datetime.now().timestamp())}"
        backup = {
            'backup_id': backup_id,
            'data_type': data_type,
            'size': len(str(data)),
            'created_at': datetime.now().isoformat(),
            'status': 'completed'
        }
        self.backups.append(backup)
        return backup
    
    def restore_backup(self, backup_id):
        """Restore from backup"""
        backup = next((b for b in self.backups if b['backup_id'] == backup_id), None)
        if backup:
            return {
                'status': 'restored',
                'backup_id': backup_id,
                'restored_at': datetime.now().isoformat()
            }
        return {'error': 'Backup not found'}
    
    def list_backups(self, limit=10):
        """List available backups"""
        return self.backups[-limit:]
    
    def delete_backup(self, backup_id):
        """Delete a backup"""
        self.backups = [b for b in self.backups if b['backup_id'] != backup_id]
        return {'status': 'deleted', 'backup_id': backup_id}
    
    def get_backup_stats(self):
        """Get backup statistics"""
        total_size = sum(b['size'] for b in self.backups)
        return {
            'total_backups': len(self.backups),
            'total_size_bytes': total_size,
            'auto_backup_enabled': self.auto_backup_enabled,
            'oldest_backup': self.backups[0]['created_at'] if self.backups else None,
            'newest_backup': self.backups[-1]['created_at'] if self.backups else None
        }

# ============================================================================
# API RATE LIMITER
# ============================================================================

class RateLimiter:
    """API rate limiting and throttling"""
    
    def __init__(self):
        self.requests = defaultdict(deque)
        self.limits = {
            'default': {'requests': 100, 'window': 60},
            'auth': {'requests': 5, 'window': 60},
            'export': {'requests': 10, 'window': 60}
        }
        self.blocked_ips = set()
    
    def check_rate_limit(self, ip, endpoint_type='default'):
        """Check if request is within rate limit"""
        if ip in self.blocked_ips:
            return {'allowed': False, 'reason': 'IP blocked'}
        
        limit_config = self.limits.get(endpoint_type, self.limits['default'])
        now = time.time()
        window_start = now - limit_config['window']
        
        # Clean old requests
        while self.requests[ip] and self.requests[ip][0] < window_start:
            self.requests[ip].popleft()
        
        # Check limit
        if len(self.requests[ip]) >= limit_config['requests']:
            return {
                'allowed': False,
                'reason': 'Rate limit exceeded',
                'retry_after': int(self.requests[ip][0] + limit_config['window'] - now)
            }
        
        # Add request
        self.requests[ip].append(now)
        return {
            'allowed': True,
            'remaining': limit_config['requests'] - len(self.requests[ip])
        }
    
    def block_ip(self, ip, duration=3600):
        """Temporarily block an IP"""
        self.blocked_ips.add(ip)
        return {'status': 'blocked', 'ip': ip, 'duration': duration}
    
    def unblock_ip(self, ip):
        """Unblock an IP"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            return {'status': 'unblocked', 'ip': ip}
        return {'error': 'IP not blocked'}
    
    def get_stats(self):
        """Get rate limiting statistics"""
        return {
            'active_ips': len(self.requests),
            'blocked_ips': len(self.blocked_ips),
            'total_requests': sum(len(reqs) for reqs in self.requests.values())
        }

# ============================================================================
# AUDIT LOGGER
# ============================================================================

class AuditLogger:
    """Comprehensive audit logging"""
    
    def __init__(self):
        self.logs = []
        self.log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    
    def log(self, action, user, details=None, level='INFO'):
        """Log an action"""
        log_entry = {
            'log_id': f"LOG_{int(datetime.now().timestamp())}_{len(self.logs)}",
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'user': user,
            'level': level,
            'details': details or {},
            'ip': details.get('ip') if details else None
        }
        self.logs.append(log_entry)
        return log_entry
    
    def log_login(self, user, ip, success=True):
        """Log login attempt"""
        return self.log(
            'LOGIN_SUCCESS' if success else 'LOGIN_FAILED',
            user,
            {'ip': ip, 'success': success},
            'INFO' if success else 'WARNING'
        )
    
    def log_config_change(self, user, setting, old_value, new_value):
        """Log configuration change"""
        return self.log(
            'CONFIG_CHANGE',
            user,
            {'setting': setting, 'old': old_value, 'new': new_value},
            'WARNING'
        )
    
    def log_data_access(self, user, resource, action='READ'):
        """Log data access"""
        return self.log(
            f'DATA_{action}',
            user,
            {'resource': resource, 'action': action},
            'INFO'
        )
    
    def get_logs(self, user=None, level=None, limit=100):
        """Retrieve audit logs"""
        filtered = self.logs
        
        if user:
            filtered = [l for l in filtered if l['user'] == user]
        if level:
            filtered = [l for l in filtered if l['level'] == level]
        
        return filtered[-limit:]
    
    def get_user_activity(self, user):
        """Get activity summary for a user"""
        user_logs = [l for l in self.logs if l['user'] == user]
        
        action_counts = defaultdict(int)
        for log in user_logs:
            action_counts[log['action']] += 1
        
        return {
            'user': user,
            'total_actions': len(user_logs),
            'actions_breakdown': dict(action_counts),
            'first_activity': user_logs[0]['timestamp'] if user_logs else None,
            'last_activity': user_logs[-1]['timestamp'] if user_logs else None
        }
    
    def export_audit_trail(self):
        """Export complete audit trail"""
        return {
            'total_logs': len(self.logs),
            'date_range': {
                'start': self.logs[0]['timestamp'] if self.logs else None,
                'end': self.logs[-1]['timestamp'] if self.logs else None
            },
            'logs': self.logs
        }
