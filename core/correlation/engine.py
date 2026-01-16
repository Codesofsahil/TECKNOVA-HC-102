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
        alerts.extend(self._detect_brute_force(normalized_log))
        alerts.extend(self._detect_port_scan(normalized_log))
        alerts.extend(self._detect_privilege_escalation(normalized_log))
        alerts.extend(self._detect_suspicious_login(normalized_log))
        return alerts
    
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
                    'description': f"Detected {len(recent_events)} failed attempts from {log['source_ip']}"
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
