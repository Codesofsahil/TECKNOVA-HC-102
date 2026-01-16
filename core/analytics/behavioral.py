from datetime import datetime
from collections import defaultdict

class BehavioralAnalytics:
    def __init__(self):
        self.user_profiles = defaultdict(lambda: {
            'login_times': [],
            'login_locations': [],
            'failed_attempts': 0,
            'baseline_established': False
        })
        self.anomalies = []
    
    def update_profile(self, user, activity):
        profile = self.user_profiles[user]
        
        if activity.get('event_type') == 'login':
            profile['login_times'].append(datetime.now().hour)
            if activity.get('source_ip'):
                profile['login_locations'].append(activity['source_ip'])
        
        if len(profile['login_times']) >= 50:
            profile['baseline_established'] = True
    
    def detect_anomalies(self, user, activity):
        profile = self.user_profiles[user]
        anomalies = []
        
        if not profile['baseline_established']:
            return anomalies
        
        if activity.get('event_type') == 'login':
            current_hour = datetime.now().hour
            if current_hour < 6 or current_hour > 22:
                anomalies.append({
                    'type': 'unusual_login_time',
                    'severity': 'MEDIUM',
                    'user': user,
                    'description': f'Login at unusual hour: {current_hour}:00'
                })
        
        if activity.get('source_ip'):
            recent_ips = profile['login_locations'][-20:]
            if activity['source_ip'] not in recent_ips:
                anomalies.append({
                    'type': 'new_location',
                    'severity': 'MEDIUM',
                    'user': user,
                    'description': f'Login from new IP: {activity["source_ip"]}'
                })
        
        self.anomalies.extend(anomalies)
        return anomalies
    
    def get_user_risk_score(self, user):
        profile = self.user_profiles[user]
        score = profile['failed_attempts'] * 5
        recent_anomalies = [a for a in self.anomalies if a['user'] == user]
        score += len(recent_anomalies) * 10
        return min(score, 100)
