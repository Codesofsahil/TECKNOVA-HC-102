import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict

class ThreatIntelligence:
    def __init__(self, config):
        self.config = config
        self.threat_cache = {}
        self.ioc_database = defaultdict(list)
        self.threat_scores = {}
        
    def check_ip_threat(self, ip):
        """Check IP against multiple threat intelligence sources"""
        if ip in self.threat_cache:
            cache_time = self.threat_cache[ip].get('timestamp')
            if datetime.now() - cache_time < timedelta(hours=1):
                return self.threat_cache[ip]['data']
        
        threat_data = {
            'ip': ip,
            'is_malicious': False,
            'threat_score': 0,
            'categories': [],
            'sources': [],
            'last_seen': None,
            'confidence': 0
        }
        
        # Check against known malicious IPs
        if self._check_malicious_ip(ip):
            threat_data['is_malicious'] = True
            threat_data['threat_score'] = 85
            threat_data['categories'].append('Known Malicious')
            threat_data['sources'].append('Internal Blacklist')
        
        # Check Tor exit nodes
        if self._check_tor_exit(ip):
            threat_data['threat_score'] += 30
            threat_data['categories'].append('Tor Exit Node')
            threat_data['sources'].append('Tor Project')
        
        # Check VPN/Proxy
        if self._check_vpn_proxy(ip):
            threat_data['threat_score'] += 20
            threat_data['categories'].append('VPN/Proxy')
        
        # Calculate confidence
        threat_data['confidence'] = min(len(threat_data['sources']) * 25, 100)
        
        # Cache result
        self.threat_cache[ip] = {
            'timestamp': datetime.now(),
            'data': threat_data
        }
        
        return threat_data
    
    def _check_malicious_ip(self, ip):
        """Check against known malicious IP database"""
        malicious_ranges = [
            '192.168.100.', '10.0.0.', '172.16.0.',
            '185.220.', '45.142.', '91.219.'
        ]
        return any(ip.startswith(r) for r in malicious_ranges)
    
    def _check_tor_exit(self, ip):
        """Check if IP is Tor exit node"""
        tor_ranges = ['185.220.', '45.142.']
        return any(ip.startswith(r) for r in tor_ranges)
    
    def _check_vpn_proxy(self, ip):
        """Check if IP is VPN/Proxy"""
        vpn_ranges = ['91.219.', '172.16.']
        return any(ip.startswith(r) for r in vpn_ranges)
    
    def add_ioc(self, ioc_type, value, source, description):
        """Add Indicator of Compromise"""
        ioc = {
            'type': ioc_type,
            'value': value,
            'source': source,
            'description': description,
            'added_at': datetime.now().isoformat(),
            'hits': 0
        }
        self.ioc_database[ioc_type].append(ioc)
        return ioc
    
    def check_ioc(self, ioc_type, value):
        """Check if value matches any IOC"""
        matches = []
        for ioc in self.ioc_database.get(ioc_type, []):
            if ioc['value'] == value or value in ioc['value']:
                ioc['hits'] += 1
                matches.append(ioc)
        return matches
    
    def get_threat_report(self, ip):
        """Generate comprehensive threat report"""
        threat_data = self.check_ip_threat(ip)
        ioc_matches = self.check_ioc('ip', ip)
        
        report = {
            'ip': ip,
            'threat_level': self._calculate_threat_level(threat_data['threat_score']),
            'threat_score': threat_data['threat_score'],
            'is_malicious': threat_data['is_malicious'],
            'categories': threat_data['categories'],
            'sources': threat_data['sources'],
            'ioc_matches': len(ioc_matches),
            'confidence': threat_data['confidence'],
            'recommendation': self._get_recommendation(threat_data['threat_score']),
            'generated_at': datetime.now().isoformat()
        }
        
        return report
    
    def _calculate_threat_level(self, score):
        if score >= 80: return 'CRITICAL'
        if score >= 60: return 'HIGH'
        if score >= 40: return 'MEDIUM'
        if score >= 20: return 'LOW'
        return 'INFO'
    
    def _get_recommendation(self, score):
        if score >= 80:
            return 'BLOCK IMMEDIATELY - High confidence malicious activity'
        if score >= 60:
            return 'INVESTIGATE - Suspicious activity detected'
        if score >= 40:
            return 'MONITOR - Potentially suspicious, continue monitoring'
        return 'ALLOW - Low risk, normal activity'
