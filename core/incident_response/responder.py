import requests
from datetime import datetime
import json

class IncidentResponder:
    def __init__(self, config):
        self.config = config
        self.incidents = []
        
    def handle_alert(self, alert, alert_manager):
        # Auto-enrich
        enrichment = self._enrich_alert(alert)
        alert_manager.enrich_alert(alert['id'], enrichment)
        
        # Auto-classify
        classification = self._classify_alert(alert)
        
        # Create incident if high severity
        if alert['severity'] in ['CRITICAL', 'HIGH']:
            incident = self._create_incident(alert, classification)
            self.incidents.append(incident)
            
            # Auto-respond
            self._auto_respond(alert, incident)
        
        return {
            'enrichment': enrichment,
            'classification': classification,
            'incident_created': alert['severity'] in ['CRITICAL', 'HIGH']
        }
    
    def _enrich_alert(self, alert):
        enrichment = {
            'enriched_at': datetime.now().isoformat(),
            'ip_reputation': self._check_ip_reputation(alert.get('source_ip')),
            'geolocation': self._get_geolocation(alert.get('source_ip')),
            'threat_intel': self._check_threat_intel(alert.get('source_ip'))
        }
        return enrichment
    
    def _check_ip_reputation(self, ip):
        if not ip:
            return {'status': 'unknown'}
        
        # Simplified reputation check
        suspicious_ranges = ['192.168.100.', '10.0.0.', '172.16.']
        if any(ip.startswith(r) for r in suspicious_ranges):
            return {'status': 'suspicious', 'score': 75}
        return {'status': 'clean', 'score': 10}
    
    def _get_geolocation(self, ip):
        if not ip:
            return {'country': 'Unknown'}
        
        # Simplified geolocation
        if ip.startswith('192.168'):
            return {'country': 'Internal', 'city': 'LAN'}
        return {'country': 'Unknown', 'city': 'Unknown'}
    
    def _check_threat_intel(self, ip):
        # Placeholder for threat intel integration
        return {'known_threat': False, 'sources': []}
    
    def _classify_alert(self, alert):
        categories = []
        
        if 'brute force' in alert['title'].lower():
            categories.append('Credential Access')
        if 'port scan' in alert['title'].lower():
            categories.append('Discovery')
        if 'privilege' in alert['title'].lower():
            categories.append('Privilege Escalation')
        
        return {
            'categories': categories,
            'mitre_tactics': self._extract_mitre_tactic(alert.get('mitre_attack', ''))
        }
    
    def _extract_mitre_tactic(self, mitre_str):
        tactics = {
            'T1110': 'Credential Access',
            'T1046': 'Discovery',
            'T1068': 'Privilege Escalation',
            'T1078': 'Persistence'
        }
        for tid, tactic in tactics.items():
            if tid in mitre_str:
                return tactic
        return 'Unknown'
    
    def _create_incident(self, alert, classification):
        incident = {
            'incident_id': f"INC_{int(datetime.now().timestamp())}",
            'alert_id': alert['id'],
            'title': alert['title'],
            'severity': alert['severity'],
            'status': 'INVESTIGATING',
            'created_at': datetime.now().isoformat(),
            'classification': classification,
            'timeline': [
                {'timestamp': datetime.now().isoformat(), 'action': 'Incident created', 'user': 'system'}
            ],
            'notes': []
        }
        return incident
    
    def _auto_respond(self, alert, incident):
        actions = []
        
        # Auto-block for critical threats
        if alert['severity'] == 'CRITICAL':
            actions.append(self._block_ip(alert.get('source_ip')))
        
        # Send notification
        actions.append(self._send_notification(alert, incident))
        
        incident['timeline'].extend(actions)
        return actions
    
    def _block_ip(self, ip):
        # Simulated IP blocking
        return {
            'timestamp': datetime.now().isoformat(),
            'action': f'Auto-blocked IP: {ip}',
            'user': 'system',
            'status': 'success'
        }
    
    def _send_notification(self, alert, incident):
        # Simulated notification
        return {
            'timestamp': datetime.now().isoformat(),
            'action': f'Notification sent for incident {incident["incident_id"]}',
            'user': 'system',
            'channel': 'email',
            'status': 'success'
        }
    
    def get_incidents(self, status=None):
        if status:
            return [i for i in self.incidents if i['status'] == status]
        return self.incidents
