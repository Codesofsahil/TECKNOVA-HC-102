from datetime import datetime, timedelta

class ComplianceReporter:
    def __init__(self):
        self.frameworks = {
            'ISO27001': ['A.12.4.1', 'A.12.4.2', 'A.12.4.3', 'A.16.1.2'],
            'NIST': ['DE.CM-1', 'DE.CM-7', 'RS.AN-1', 'RS.AN-2'],
            'PCI-DSS': ['10.1', '10.2', '10.3', '10.6'],
            'GDPR': ['Article 32', 'Article 33', 'Article 34']
        }
    
    def generate_compliance_report(self, framework, alerts, incidents, timeframe_days=30):
        cutoff = datetime.now() - timedelta(days=timeframe_days)
        
        report = {
            'framework': framework,
            'period': f'Last {timeframe_days} days',
            'generated_at': datetime.now().isoformat(),
            'metrics': self._calculate_metrics(alerts, incidents, cutoff),
            'controls': self._map_controls(framework, alerts, incidents),
            'compliance_score': 0,
            'recommendations': []
        }
        
        report['compliance_score'] = self._calculate_compliance_score(report['metrics'])
        report['recommendations'] = self._generate_recommendations(report['metrics'])
        
        return report
    
    def _calculate_metrics(self, alerts, incidents, cutoff):
        recent_alerts = [a for a in alerts if datetime.fromisoformat(a['timestamp']) > cutoff]
        recent_incidents = [i for i in incidents if datetime.fromisoformat(i['created_at']) > cutoff]
        
        critical_alerts = [a for a in recent_alerts if a['severity'] == 'CRITICAL']
        resolved_incidents = [i for i in recent_incidents if i['status'] == 'RESOLVED']
        
        avg_response_time = 0
        if resolved_incidents:
            response_times = []
            for inc in resolved_incidents:
                start = datetime.fromisoformat(inc['created_at'])
                end = datetime.fromisoformat(inc.get('updated_at', inc['created_at']))
                response_times.append((end - start).total_seconds() / 60)
            avg_response_time = sum(response_times) / len(response_times)
        
        return {
            'total_alerts': len(recent_alerts),
            'critical_alerts': len(critical_alerts),
            'total_incidents': len(recent_incidents),
            'resolved_incidents': len(resolved_incidents),
            'avg_response_time_minutes': round(avg_response_time, 2),
            'detection_rate': round(len(recent_alerts) / max(len(recent_incidents), 1), 2)
        }
    
    def _map_controls(self, framework, alerts, incidents):
        controls = []
        
        if framework == 'ISO27001':
            controls = [
                {'control': 'A.12.4.1', 'name': 'Event logging', 'status': 'Compliant', 'evidence': f'{len(alerts)} events logged'},
                {'control': 'A.16.1.2', 'name': 'Reporting security events', 'status': 'Compliant', 'evidence': f'{len(incidents)} incidents reported'}
            ]
        elif framework == 'NIST':
            controls = [
                {'control': 'DE.CM-1', 'name': 'Network monitored', 'status': 'Compliant', 'evidence': 'Continuous monitoring active'},
                {'control': 'RS.AN-1', 'name': 'Notifications sent', 'status': 'Compliant', 'evidence': 'Automated alerting enabled'}
            ]
        
        return controls
    
    def _calculate_compliance_score(self, metrics):
        score = 100
        
        if metrics['avg_response_time_minutes'] > 60:
            score -= 20
        
        if metrics['critical_alerts'] > 10:
            score -= 15
        
        resolution_rate = metrics['resolved_incidents'] / max(metrics['total_incidents'], 1)
        if resolution_rate < 0.8:
            score -= 25
        
        return max(score, 0)
    
    def _generate_recommendations(self, metrics):
        recommendations = []
        
        if metrics['avg_response_time_minutes'] > 60:
            recommendations.append('Reduce average response time to under 60 minutes')
        
        if metrics['critical_alerts'] > 10:
            recommendations.append('Investigate high number of critical alerts')
        
        resolution_rate = metrics['resolved_incidents'] / max(metrics['total_incidents'], 1)
        if resolution_rate < 0.8:
            recommendations.append('Improve incident resolution rate to 80%+')
        
        return recommendations
