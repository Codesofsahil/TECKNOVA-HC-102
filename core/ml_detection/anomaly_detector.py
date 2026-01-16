import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta

class AnomalyDetector:
    def __init__(self, config):
        self.config = config
        self.baselines = defaultdict(list)
        self.anomalies = []
        
    def detect_anomalies(self, logs):
        anomalies = []
        anomalies.extend(self._detect_traffic_anomaly(logs))
        anomalies.extend(self._detect_time_anomaly(logs))
        return anomalies
    
    def _detect_traffic_anomaly(self, logs):
        # Count events per source IP
        ip_counts = defaultdict(int)
        for log in logs:
            if log.get('source_ip'):
                ip_counts[log['source_ip']] += 1
        
        if not ip_counts:
            return []
        
        counts = list(ip_counts.values())
        mean = np.mean(counts)
        std = np.std(counts)
        
        if std == 0:
            return []
        
        anomalies = []
        for ip, count in ip_counts.items():
            z_score = (count - mean) / std
            if abs(z_score) > self.config.ANOMALY_THRESHOLD:
                anomalies.append({
                    'alert_id': f"ANOM_TRAFFIC_{ip}_{int(datetime.now().timestamp())}",
                    'title': 'Traffic Volume Anomaly',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'event_count': count,
                    'z_score': round(z_score, 2),
                    'timestamp': datetime.now().isoformat(),
                    'description': f"Unusual traffic volume from {ip}: {count} events (z-score: {z_score:.2f})"
                })
        
        return anomalies
    
    def _detect_time_anomaly(self, logs):
        # Detect activity during unusual hours (e.g., 2-5 AM)
        anomalies = []
        for log in logs:
            try:
                timestamp = datetime.fromisoformat(log['timestamp']) if isinstance(log['timestamp'], str) else datetime.now()
                hour = timestamp.hour
                
                if 2 <= hour <= 5:  # Unusual hours
                    anomalies.append({
                        'alert_id': f"ANOM_TIME_{log.get('source_ip', 'unknown')}_{int(datetime.now().timestamp())}",
                        'title': 'Unusual Time Activity',
                        'severity': 'LOW',
                        'source_ip': log.get('source_ip'),
                        'timestamp': log['timestamp'],
                        'hour': hour,
                        'description': f"Activity detected during unusual hours ({hour}:00)"
                    })
            except:
                pass
        
        return anomalies
    
    def update_baseline(self, logs):
        # Update baseline statistics
        for log in logs:
            if log.get('source_ip'):
                self.baselines[log['source_ip']].append({
                    'timestamp': datetime.now(),
                    'event_type': log.get('event_type')
                })
        
        # Keep only last 24 hours
        cutoff = datetime.now() - timedelta(hours=24)
        for ip in self.baselines:
            self.baselines[ip] = [e for e in self.baselines[ip] if e['timestamp'] > cutoff]
