from datetime import datetime, timedelta
from collections import defaultdict
import json

class CorrelationEngine:
    def __init__(self, config):
        self.config = config
        self.event_cache = defaultdict(list)
        self.alerts = []
        
    def analyze(self, normalized_log):
        alerts = []
<<<<<<< HEAD
        
        # Check if log already has severity (from test generator)
        if normalized_log.get('severity'):
            # Create alert directly from log with specified severity
            alert = {
                'alert_id': f"{normalized_log['event_type'].upper()}_{normalized_log['source_ip']}_{int(datetime.now().timestamp())}",
                'title': self._get_alert_title(normalized_log['event_type']),
                'severity': normalized_log['severity'],
                'source_ip': normalized_log['source_ip'],
                'timestamp': datetime.now().isoformat(),
                'mitre_attack': self._get_mitre_technique(normalized_log['event_type']),
                'description': normalized_log.get('message', 'Security event detected'),
                'priority_score': self._calculate_priority_score(normalized_log['severity'])
            }
            alerts.append(alert)
        
        # Run correlation detection
=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
        alerts.extend(self._detect_brute_force(normalized_log))
        alerts.extend(self._detect_port_scan(normalized_log))
        alerts.extend(self._detect_privilege_escalation(normalized_log))
        alerts.extend(self._detect_suspicious_login(normalized_log))
        return alerts
    
<<<<<<< HEAD
    def _get_alert_title(self, event_type):
        titles = {
            'ransomware': 'Ransomware Attack Detected',
            'data_exfiltration': 'Data Exfiltration Detected',
            'backdoor_access': 'Backdoor Access Detected',
            'privilege_escalation': 'Privilege Escalation Detected',
            'lateral_movement': 'Lateral Movement Detected',
            'malware_detected': 'Malware Detected',
            'credential_stuffing': 'Credential Stuffing Attack',
            'sql_injection': 'SQL Injection Attempt',
            'xss_attack': 'Cross-Site Scripting Attack',
            'phishing_attempt': 'Phishing Attempt Detected',
            'port_scan': 'Port Scan Detected',
            'dns_tunneling': 'DNS Tunneling Detected',
            'login_success': 'Unusual Login Activity',
            'file_access': 'Sensitive File Access',
            'policy_violation': 'Security Policy Violation',
            'suspicious_user_agent': 'Suspicious User Agent',
            'bandwidth_anomaly': 'Network Bandwidth Anomaly',
            'configuration_change': 'System Configuration Change'
        }
        return titles.get(event_type, 'Security Alert')
    
    def _get_mitre_technique(self, event_type):
        techniques = {
            'ransomware': 'T1486 - Data Encrypted for Impact',
            'data_exfiltration': 'T1041 - Exfiltration Over C2 Channel',
            'backdoor_access': 'T1071 - Application Layer Protocol',
            'privilege_escalation': 'T1068 - Exploitation for Privilege Escalation',
            'lateral_movement': 'T1021 - Remote Services',
            'malware_detected': 'T1204 - User Execution',
            'credential_stuffing': 'T1110.004 - Credential Stuffing',
            'sql_injection': 'T1190 - Exploit Public-Facing Application',
            'xss_attack': 'T1190 - Exploit Public-Facing Application',
            'phishing_attempt': 'T1566 - Phishing',
            'port_scan': 'T1046 - Network Service Discovery',
            'dns_tunneling': 'T1071.004 - DNS',
            'login_success': 'T1078 - Valid Accounts',
            'file_access': 'T1083 - File and Directory Discovery',
            'policy_violation': 'T1562 - Impair Defenses',
            'suspicious_user_agent': 'T1071.001 - Web Protocols',
            'bandwidth_anomaly': 'T1041 - Exfiltration Over C2 Channel',
            'configuration_change': 'T1562.001 - Disable or Modify Tools'
        }
        return techniques.get(event_type, 'T1059 - Command and Scripting Interpreter')
    
    def _calculate_priority_score(self, severity):
        scores = {
            'CRITICAL': 9.5,
            'HIGH': 7.8,
            'MEDIUM': 5.2,
            'LOW': 2.1,
            'INFO': 1.0
        }
        return scores.get(severity, 5.0)
    
=======
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
    def _detect_brute_force(self, log):
        if 'failed' in str(log.get('message', '')).lower() or log.get('action') == 'DENY':
            key = f"brute_force_{log['source_ip']}"
            self.event_cache[key].append({
                'timestamp': datetime.fromisoformat(log['timestamp']) if isinstance(log['timestamp'], str) else datetime.now(),
                'target': log.get('dest_ip') or log.get('user')
            })
            
            window_start = datetime.now() - timedelta(seconds=self.config.BRUTE_FORCE_WINDOW)
            recent_events = [e for e in self.event_cache[key] if e['timestamp'] > window_start]
            self.event_cache[key] = recent_events
            
            if len(recent_events) >= self.config.BRUTE_FORCE_THRESHOLD:
                return [{
                    'alert_id': f"BF_{log['source_ip']}_{int(datetime.now().timestamp())}",
                    'title': 'Brute Force Attack Detected',
                    'severity': 'HIGH',
                    'source_ip': log['source_ip'],
                    'target': recent_events[0]['target'],
                    'count': len(recent_events),
                    'timestamp': datetime.now().isoformat(),
                    'mitre_attack': 'T1110 - Brute Force',
<<<<<<< HEAD
                    'description': f"Detected {len(recent_events)} failed attempts from {log['source_ip']}",
                    'priority_score': 7.8
=======
                    'description': f"Detected {len(recent_events)} failed attempts from {log['source_ip']}"
>>>>>>> fcd86bfc6412671002f4a4b3bd4aec468bd27fc2
                }]
        return []
    
    def _detect_port_scan(self, log):
        if log.get('dest_port'):
            key = f"port_scan_{log['source_ip']}"
            self.event_cache[key].append({
                'timestamp': datetime.now(),
                'port': log['dest_port']
            })
            
            window_start = datetime.now() - timedelta(seconds=self.config.PORT_SCAN_WINDOW)
            recent_events = [e for e in self.event_cache[key] if e['timestamp'] > window_start]
            unique_ports = len(set(e['port'] for e in recent_events))
            
            if unique_ports >= self.config.PORT_SCAN_THRESHOLD:
                return [{
                    'alert_id': f"PS_{log['source_ip']}_{int(datetime.now().timestamp())}",
                    'title': 'Port Scan Detected',
                    'severity': 'MEDIUM',
                    'source_ip': log['source_ip'],
                    'ports_scanned': unique_ports,
                    'timestamp': datetime.now().isoformat(),
                    'mitre_attack': 'T1046 - Network Service Discovery',
                    'description': f"Detected scanning of {unique_ports} ports from {log['source_ip']}"
                }]
        return []
    
    def _detect_privilege_escalation(self, log):
        escalation_keywords = ['sudo', 'runas', 'privilege', 'administrator', 'root']
        message = str(log.get('message', '')).lower()
        
        if any(keyword in message for keyword in escalation_keywords):
            return [{
                'alert_id': f"PE_{log.get('user', 'unknown')}_{int(datetime.now().timestamp())}",
                'title': 'Privilege Escalation Attempt',
                'severity': 'CRITICAL',
                'user': log.get('user'),
                'source_ip': log.get('source_ip'),
                'timestamp': datetime.now().isoformat(),
                'mitre_attack': 'T1068 - Exploitation for Privilege Escalation',
                'description': f"Potential privilege escalation by {log.get('user')}"
            }]
        return []
    
    def _detect_suspicious_login(self, log):
        if 'login' in str(log.get('message', '')).lower():
            if log.get('source_ip'):
                # Check for login from unusual location (simplified)
                suspicious_ips = ['192.168.100.', '10.0.0.']
                if any(log['source_ip'].startswith(ip) for ip in suspicious_ips):
                    return [{
                        'alert_id': f"SL_{log['source_ip']}_{int(datetime.now().timestamp())}",
                        'title': 'Suspicious Login Location',
                        'severity': 'MEDIUM',
                        'source_ip': log['source_ip'],
                        'user': log.get('user'),
                        'timestamp': datetime.now().isoformat(),
                        'mitre_attack': 'T1078 - Valid Accounts',
                        'description': f"Login from suspicious IP {log['source_ip']}"
                    }]
        return []
