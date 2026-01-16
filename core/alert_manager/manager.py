from datetime import datetime
import json

class AlertManager:
    def __init__(self, config):
        self.config = config
        self.alerts = []
        self.alert_counts = {}
        
    def create_alert(self, alert_data):
        alert = {
            'id': alert_data.get('alert_id'),
            'title': alert_data.get('title'),
            'severity': alert_data.get('severity', 'MEDIUM'),
            'priority_score': self._calculate_priority(alert_data),
            'status': 'NEW',
            'timestamp': alert_data.get('timestamp', datetime.now().isoformat()),
            'source_ip': alert_data.get('source_ip'),
            'mitre_attack': alert_data.get('mitre_attack'),
            'description': alert_data.get('description'),
            'enrichment': {},
            'actions_taken': []
        }
        
        # Deduplication
        if not self._is_duplicate(alert):
            self.alerts.append(alert)
            self._update_alert_count(alert)
            return alert
        return None
    
    def _calculate_priority(self, alert_data):
        severity_score = self.config.ALERT_SEVERITY.get(alert_data.get('severity', 'MEDIUM'), 3)
        frequency_score = self.alert_counts.get(alert_data.get('alert_id', ''), 0) * 0.5
        
        # Asset criticality (simplified)
        asset_score = 0
        if alert_data.get('dest_ip', '').startswith('10.0.1.'):
            asset_score = 2  # Critical subnet
        
        priority = severity_score + frequency_score + asset_score
        return min(priority, 10)
    
    def _is_duplicate(self, alert):
        for existing in self.alerts[-10:]:
            if (existing['title'] == alert['title'] and 
                existing['source_ip'] == alert['source_ip'] and
                existing['status'] == 'NEW'):
                time_diff = datetime.now() - datetime.fromisoformat(existing['timestamp'])
                if time_diff.total_seconds() < 300:  # 5 minutes
                    return True
        return False
    
    def _update_alert_count(self, alert):
        key = alert['id'].split('_')[0]
        self.alert_counts[key] = self.alert_counts.get(key, 0) + 1
    
    def get_alerts(self, status=None, severity=None, limit=100):
        filtered = self.alerts
        if status:
            filtered = [a for a in filtered if a['status'] == status]
        if severity:
            filtered = [a for a in filtered if a['severity'] == severity]
        
        # Sort by priority score
        filtered.sort(key=lambda x: x['priority_score'], reverse=True)
        return filtered[:limit]
    
    def update_alert_status(self, alert_id, status):
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['status'] = status
                alert['updated_at'] = datetime.now().isoformat()
                return True
        return False
    
    def enrich_alert(self, alert_id, enrichment_data):
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['enrichment'].update(enrichment_data)
                return True
        return False
