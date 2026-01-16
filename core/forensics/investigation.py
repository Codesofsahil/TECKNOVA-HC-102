from datetime import datetime
import json

class ForensicsEngine:
    def __init__(self):
        self.investigations = []
        self.evidence_chain = []
    
    def start_investigation(self, alert_id, incident_id):
        investigation = {
            'investigation_id': f"INV_{int(datetime.now().timestamp())}",
            'alert_id': alert_id,
            'incident_id': incident_id,
            'started_at': datetime.now().isoformat(),
            'status': 'active',
            'evidence': [],
            'timeline': [],
            'findings': []
        }
        self.investigations.append(investigation)
        return investigation
    
    def collect_evidence(self, investigation_id, evidence_type, data):
        evidence = {
            'evidence_id': f"EVD_{int(datetime.now().timestamp())}",
            'type': evidence_type,
            'data': data,
            'collected_at': datetime.now().isoformat(),
            'hash': f"SHA256:{hash(str(data))}"
        }
        
        for inv in self.investigations:
            if inv['investigation_id'] == investigation_id:
                inv['evidence'].append(evidence)
                self.evidence_chain.append(evidence)
                break
        
        return evidence
    
    def analyze_logs(self, investigation_id, logs):
        findings = []
        
        # Pattern analysis
        ip_frequency = {}
        for log in logs:
            ip = log.get('source_ip')
            if ip:
                ip_frequency[ip] = ip_frequency.get(ip, 0) + 1
        
        for ip, count in ip_frequency.items():
            if count > 10:
                findings.append({
                    'type': 'high_frequency_access',
                    'ip': ip,
                    'count': count,
                    'severity': 'MEDIUM'
                })
        
        for inv in self.investigations:
            if inv['investigation_id'] == investigation_id:
                inv['findings'].extend(findings)
                break
        
        return findings
    
    def generate_report(self, investigation_id):
        for inv in self.investigations:
            if inv['investigation_id'] == investigation_id:
                report = {
                    'investigation_id': inv['investigation_id'],
                    'status': inv['status'],
                    'evidence_count': len(inv['evidence']),
                    'findings_count': len(inv['findings']),
                    'timeline': inv['timeline'],
                    'summary': f"Investigation {investigation_id} - {len(inv['findings'])} findings",
                    'generated_at': datetime.now().isoformat()
                }
                return report
        return None
