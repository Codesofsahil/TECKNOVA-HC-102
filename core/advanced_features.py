"""
Advanced Features Module - Batch 4
Real-time WebSocket, Mobile Push, Cloud Storage, Threat Hunting,
Asset Management, Threat Modeling, Performance Monitoring
"""

from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import hashlib
import time
import threading
import queue

# ============================================================================
# REAL-TIME WEBSOCKET MANAGER
# ============================================================================

class WebSocketManager:
    """Real-time dashboard updates via WebSocket"""
    
    def __init__(self):
        self.connections = set()
        self.message_queue = queue.Queue()
        self.active = True
        self.stats_cache = {}
        
    def add_connection(self, websocket):
        """Add new WebSocket connection"""
        self.connections.add(websocket)
        return len(self.connections)
    
    def remove_connection(self, websocket):
        """Remove WebSocket connection"""
        if websocket in self.connections:
            self.connections.remove(websocket)
        return len(self.connections)
    
    def broadcast_alert(self, alert):
        """Broadcast new alert to all connected clients"""
        message = {
            'type': 'new_alert',
            'data': alert,
            'timestamp': datetime.now().isoformat()
        }
        self._broadcast(message)
    
    def broadcast_stats_update(self, stats):
        """Broadcast dashboard stats update"""
        message = {
            'type': 'stats_update',
            'data': stats,
            'timestamp': datetime.now().isoformat()
        }
        self._broadcast(message)
    
    def broadcast_incident_update(self, incident):
        """Broadcast incident status update"""
        message = {
            'type': 'incident_update',
            'data': incident,
            'timestamp': datetime.now().isoformat()
        }
        self._broadcast(message)
    
    def _broadcast(self, message):
        """Send message to all connected clients"""
        disconnected = set()
        for connection in self.connections:
            try:
                connection.send(json.dumps(message))
            except:
                disconnected.add(connection)
        
        # Remove disconnected clients
        self.connections -= disconnected
    
    def get_connection_stats(self):
        """Get WebSocket connection statistics"""
        return {
            'active_connections': len(self.connections),
            'messages_sent': self.message_queue.qsize(),
            'uptime': time.time() - getattr(self, 'start_time', time.time())
        }

# ============================================================================
# MOBILE PUSH NOTIFICATIONS
# ============================================================================

class MobilePushManager:
    """Mobile push notification service"""
    
    def __init__(self):
        self.devices = {}
        self.notification_history = []
        self.push_settings = {
            'critical_alerts': True,
            'high_alerts': True,
            'incident_updates': True,
            'system_status': False
        }
    
    def register_device(self, user_id, device_token, platform='ios'):
        """Register mobile device for push notifications"""
        device_id = hashlib.md5(device_token.encode()).hexdigest()[:8]
        self.devices[device_id] = {
            'user_id': user_id,
            'device_token': device_token,
            'platform': platform,
            'registered_at': datetime.now().isoformat(),
            'active': True
        }
        return device_id
    
    def send_alert_notification(self, alert, user_ids=None):
        """Send push notification for security alert"""
        if not self.push_settings.get('critical_alerts') and alert['severity'] == 'CRITICAL':
            return
        if not self.push_settings.get('high_alerts') and alert['severity'] == 'HIGH':
            return
        
        notification = {
            'title': f"🚨 {alert['severity']} Alert",
            'body': alert['title'],
            'data': {
                'alert_id': alert['id'],
                'severity': alert['severity'],
                'source_ip': alert.get('source_ip')
            },
            'sound': 'critical' if alert['severity'] == 'CRITICAL' else 'default'
        }
        
        return self._send_notification(notification, user_ids)
    
    def send_incident_notification(self, incident, user_ids=None):
        """Send push notification for incident update"""
        if not self.push_settings.get('incident_updates'):
            return
        
        notification = {
            'title': f"📋 Incident {incident['status']}",
            'body': f"Incident {incident['incident_id']}: {incident['title']}",
            'data': {
                'incident_id': incident['incident_id'],
                'status': incident['status']
            }
        }
        
        return self._send_notification(notification, user_ids)
    
    def _send_notification(self, notification, user_ids=None):
        """Send notification to devices"""
        sent_count = 0
        target_devices = self.devices.values()
        
        if user_ids:
            target_devices = [d for d in target_devices if d['user_id'] in user_ids]
        
        for device in target_devices:
            if device['active']:
                # Simulate push notification send
                push_record = {
                    'device_id': device['device_token'][:8] + '...',
                    'platform': device['platform'],
                    'notification': notification,
                    'sent_at': datetime.now().isoformat(),
                    'status': 'sent'
                }
                self.notification_history.append(push_record)
                sent_count += 1
        
        return {'sent': sent_count, 'total_devices': len(target_devices)}
    
    def get_device_stats(self):
        """Get mobile device statistics"""
        platforms = defaultdict(int)
        for device in self.devices.values():
            platforms[device['platform']] += 1
        
        return {
            'total_devices': len(self.devices),
            'active_devices': len([d for d in self.devices.values() if d['active']]),
            'platforms': dict(platforms),
            'notifications_sent': len(self.notification_history)
        }

# ============================================================================
# CLOUD STORAGE INTEGRATION
# ============================================================================

class CloudStorageManager:
    """Cloud storage integration for logs and backups"""
    
    def __init__(self):
        self.providers = {
            'aws_s3': {'enabled': False, 'bucket': None, 'region': 'us-east-1'},
            'azure_blob': {'enabled': False, 'container': None, 'account': None},
            'gcp_storage': {'enabled': False, 'bucket': None, 'project': None}
        }
        self.upload_queue = deque()
        self.upload_history = []
        self.sync_settings = {
            'auto_upload': True,
            'retention_days': 90,
            'compress': True,
            'encrypt': True
        }
    
    def configure_provider(self, provider, config):
        """Configure cloud storage provider"""
        if provider in self.providers:
            self.providers[provider].update(config)
            self.providers[provider]['enabled'] = True
            return {'status': 'configured', 'provider': provider}
        return {'error': 'Invalid provider'}
    
    def upload_logs(self, logs, provider='aws_s3'):
        """Upload logs to cloud storage"""
        if not self.providers[provider]['enabled']:
            return {'error': 'Provider not configured'}
        
        upload_id = f"UPLOAD_{int(datetime.now().timestamp())}"
        
        # Simulate cloud upload
        upload_record = {
            'upload_id': upload_id,
            'provider': provider,
            'data_type': 'logs',
            'record_count': len(logs),
            'size_bytes': len(json.dumps(logs)),
            'compressed': self.sync_settings['compress'],
            'encrypted': self.sync_settings['encrypt'],
            'uploaded_at': datetime.now().isoformat(),
            'status': 'completed',
            'cloud_path': f"soc-logs/{datetime.now().strftime('%Y/%m/%d')}/{upload_id}.json"
        }
        
        self.upload_history.append(upload_record)
        return upload_record
    
    def upload_backup(self, backup_data, backup_type, provider='aws_s3'):
        """Upload backup to cloud storage"""
        if not self.providers[provider]['enabled']:
            return {'error': 'Provider not configured'}
        
        upload_id = f"BACKUP_{int(datetime.now().timestamp())}"
        
        upload_record = {
            'upload_id': upload_id,
            'provider': provider,
            'data_type': f'backup_{backup_type}',
            'size_bytes': len(json.dumps(backup_data)),
            'uploaded_at': datetime.now().isoformat(),
            'status': 'completed',
            'cloud_path': f"soc-backups/{backup_type}/{upload_id}.json",
            'retention_until': (datetime.now() + timedelta(days=self.sync_settings['retention_days'])).isoformat()
        }
        
        self.upload_history.append(upload_record)
        return upload_record
    
    def sync_data(self, data_type='all'):
        """Sync data to cloud storage"""
        synced = []
        
        if data_type in ['all', 'logs']:
            # Simulate log sync
            synced.append({'type': 'logs', 'records': 100, 'status': 'synced'})
        
        if data_type in ['all', 'backups']:
            # Simulate backup sync
            synced.append({'type': 'backups', 'records': 5, 'status': 'synced'})
        
        return {
            'sync_id': f"SYNC_{int(datetime.now().timestamp())}",
            'synced_at': datetime.now().isoformat(),
            'results': synced
        }
    
    def get_storage_stats(self):
        """Get cloud storage statistics"""
        total_uploads = len(self.upload_history)
        total_size = sum(u['size_bytes'] for u in self.upload_history)
        
        providers_used = set(u['provider'] for u in self.upload_history)
        
        return {
            'total_uploads': total_uploads,
            'total_size_bytes': total_size,
            'providers_configured': len([p for p in self.providers.values() if p['enabled']]),
            'providers_used': list(providers_used),
            'auto_sync_enabled': self.sync_settings['auto_upload']
        }

# ============================================================================
# ADVANCED THREAT HUNTING
# ============================================================================

class ThreatHuntingEngine:
    """Advanced threat hunting and investigation tools"""
    
    def __init__(self):
        self.hunt_queries = {}
        self.hunt_results = []
        self.ioc_patterns = {
            'ip_patterns': [],
            'domain_patterns': [],
            'file_hash_patterns': [],
            'behavioral_patterns': []
        }
        self.hunting_rules = []
        
    def create_hunt_query(self, name, query, description):
        """Create new threat hunting query"""
        hunt_id = f"HUNT_{int(datetime.now().timestamp())}"
        
        hunt_query = {
            'hunt_id': hunt_id,
            'name': name,
            'query': query,
            'description': description,
            'created_at': datetime.now().isoformat(),
            'last_run': None,
            'results_count': 0,
            'active': True
        }
        
        self.hunt_queries[hunt_id] = hunt_query
        return hunt_query
    
    def execute_hunt(self, hunt_id, data_sources):
        """Execute threat hunting query"""
        if hunt_id not in self.hunt_queries:
            return {'error': 'Hunt query not found'}
        
        hunt = self.hunt_queries[hunt_id]
        
        # Simulate threat hunting execution
        results = self._simulate_hunt_execution(hunt['query'], data_sources)
        
        hunt_result = {
            'execution_id': f"EXEC_{int(datetime.now().timestamp())}",
            'hunt_id': hunt_id,
            'hunt_name': hunt['name'],
            'executed_at': datetime.now().isoformat(),
            'data_sources': data_sources,
            'results': results,
            'matches_found': len(results),
            'execution_time_ms': 1250
        }
        
        self.hunt_results.append(hunt_result)
        hunt['last_run'] = datetime.now().isoformat()
        hunt['results_count'] = len(results)
        
        return hunt_result
    
    def _simulate_hunt_execution(self, query, data_sources):
        """Simulate threat hunting query execution"""
        # Simulate finding suspicious patterns
        results = []
        
        if 'suspicious' in query.lower():
            results.extend([
                {
                    'type': 'suspicious_login',
                    'source_ip': '192.168.100.25',
                    'timestamp': datetime.now().isoformat(),
                    'confidence': 0.85
                },
                {
                    'type': 'unusual_process',
                    'host': 'workstation-01',
                    'process': 'powershell.exe',
                    'confidence': 0.75
                }
            ])
        
        if 'lateral' in query.lower():
            results.append({
                'type': 'lateral_movement',
                'source_host': 'server-01',
                'target_host': 'server-02',
                'method': 'SMB',
                'confidence': 0.90
            })
        
        return results
    
    def add_ioc_pattern(self, pattern_type, pattern, description):
        """Add Indicator of Compromise pattern"""
        if pattern_type in self.ioc_patterns:
            ioc = {
                'pattern': pattern,
                'description': description,
                'added_at': datetime.now().isoformat(),
                'hits': 0
            }
            self.ioc_patterns[pattern_type].append(ioc)
            return ioc
        return {'error': 'Invalid pattern type'}
    
    def hunt_iocs(self, data_sources):
        """Hunt for known IOCs in data"""
        matches = []
        
        for pattern_type, patterns in self.ioc_patterns.items():
            for pattern in patterns:
                # Simulate IOC matching
                if pattern['pattern'] in str(data_sources):
                    match = {
                        'pattern_type': pattern_type,
                        'pattern': pattern['pattern'],
                        'description': pattern['description'],
                        'matched_at': datetime.now().isoformat(),
                        'confidence': 0.95
                    }
                    matches.append(match)
                    pattern['hits'] += 1
        
        return {
            'hunt_id': f"IOC_HUNT_{int(datetime.now().timestamp())}",
            'matches': matches,
            'total_matches': len(matches),
            'executed_at': datetime.now().isoformat()
        }
    
    def get_hunt_statistics(self):
        """Get threat hunting statistics"""
        total_hunts = len(self.hunt_queries)
        total_executions = len(self.hunt_results)
        total_matches = sum(r['matches_found'] for r in self.hunt_results)
        
        return {
            'total_hunt_queries': total_hunts,
            'total_executions': total_executions,
            'total_matches': total_matches,
            'active_hunts': len([h for h in self.hunt_queries.values() if h['active']]),
            'avg_matches_per_hunt': total_matches / max(total_executions, 1)
        }

# ============================================================================
# ASSET MANAGEMENT
# ============================================================================

class AssetManager:
    """IT Asset management and tracking"""
    
    def __init__(self):
        self.assets = {}
        self.asset_groups = {}
        self.vulnerabilities = defaultdict(list)
        self.asset_history = []
        
    def register_asset(self, asset_data):
        """Register new IT asset"""
        asset_id = f"ASSET_{int(datetime.now().timestamp())}"
        
        asset = {
            'asset_id': asset_id,
            'name': asset_data.get('name'),
            'type': asset_data.get('type', 'server'),  # server, workstation, network_device
            'ip_address': asset_data.get('ip_address'),
            'mac_address': asset_data.get('mac_address'),
            'os': asset_data.get('os'),
            'version': asset_data.get('version'),
            'owner': asset_data.get('owner'),
            'location': asset_data.get('location'),
            'criticality': asset_data.get('criticality', 'medium'),  # low, medium, high, critical
            'status': 'active',
            'registered_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'security_score': self._calculate_security_score(asset_data)
        }
        
        self.assets[asset_id] = asset
        self._log_asset_change('registered', asset_id, asset_data.get('name'))
        
        return asset
    
    def update_asset(self, asset_id, updates):
        """Update asset information"""
        if asset_id not in self.assets:
            return {'error': 'Asset not found'}
        
        old_data = self.assets[asset_id].copy()
        self.assets[asset_id].update(updates)
        self.assets[asset_id]['updated_at'] = datetime.now().isoformat()
        
        self._log_asset_change('updated', asset_id, updates)
        return self.assets[asset_id]
    
    def _calculate_security_score(self, asset_data):
        """Calculate asset security score"""
        score = 100
        
        # Deduct points for missing security features
        if not asset_data.get('antivirus'):
            score -= 20
        if not asset_data.get('firewall'):
            score -= 15
        if not asset_data.get('encryption'):
            score -= 25
        if asset_data.get('os_outdated'):
            score -= 30
        
        return max(score, 0)
    
    def create_asset_group(self, name, asset_ids, description=''):
        """Create asset group"""
        group_id = f"GROUP_{int(datetime.now().timestamp())}"
        
        group = {
            'group_id': group_id,
            'name': name,
            'description': description,
            'asset_ids': asset_ids,
            'created_at': datetime.now().isoformat(),
            'asset_count': len(asset_ids)
        }
        
        self.asset_groups[group_id] = group
        return group
    
    def get_assets_by_criticality(self, criticality):
        """Get assets by criticality level"""
        return [asset for asset in self.assets.values() if asset['criticality'] == criticality]
    
    def get_vulnerable_assets(self):
        """Get assets with known vulnerabilities"""
        vulnerable = []
        for asset_id, vulns in self.vulnerabilities.items():
            if vulns and asset_id in self.assets:
                asset = self.assets[asset_id].copy()
                asset['vulnerability_count'] = len(vulns)
                asset['highest_severity'] = max(v['severity'] for v in vulns)
                vulnerable.append(asset)
        
        return sorted(vulnerable, key=lambda x: x['vulnerability_count'], reverse=True)
    
    def _log_asset_change(self, action, asset_id, details):
        """Log asset changes"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'asset_id': asset_id,
            'details': details
        }
        self.asset_history.append(log_entry)
    
    def get_asset_statistics(self):
        """Get asset management statistics"""
        total_assets = len(self.assets)
        asset_types = defaultdict(int)
        criticality_counts = defaultdict(int)
        
        for asset in self.assets.values():
            asset_types[asset['type']] += 1
            criticality_counts[asset['criticality']] += 1
        
        return {
            'total_assets': total_assets,
            'asset_types': dict(asset_types),
            'criticality_distribution': dict(criticality_counts),
            'vulnerable_assets': len(self.get_vulnerable_assets()),
            'asset_groups': len(self.asset_groups)
        }

# ============================================================================
# THREAT MODELING ENGINE
# ============================================================================

class ThreatModelingEngine:
    """Threat modeling and risk assessment"""
    
    def __init__(self):
        self.threat_models = {}
        self.attack_vectors = []
        self.risk_assessments = []
        self.mitigation_strategies = {}
        
    def create_threat_model(self, name, assets, description=''):
        """Create new threat model"""
        model_id = f"MODEL_{int(datetime.now().timestamp())}"
        
        threat_model = {
            'model_id': model_id,
            'name': name,
            'description': description,
            'assets': assets,
            'threats': [],
            'vulnerabilities': [],
            'attack_vectors': [],
            'risk_score': 0,
            'created_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat()
        }
        
        self.threat_models[model_id] = threat_model
        return threat_model
    
    def add_threat_to_model(self, model_id, threat_data):
        """Add threat to threat model"""
        if model_id not in self.threat_models:
            return {'error': 'Threat model not found'}
        
        threat = {
            'threat_id': f"THREAT_{int(datetime.now().timestamp())}",
            'name': threat_data.get('name'),
            'description': threat_data.get('description'),
            'likelihood': threat_data.get('likelihood', 'medium'),  # low, medium, high
            'impact': threat_data.get('impact', 'medium'),
            'attack_vector': threat_data.get('attack_vector'),
            'mitre_technique': threat_data.get('mitre_technique'),
            'risk_score': self._calculate_risk_score(
                threat_data.get('likelihood', 'medium'),
                threat_data.get('impact', 'medium')
            ),
            'added_at': datetime.now().isoformat()
        }
        
        self.threat_models[model_id]['threats'].append(threat)
        self._update_model_risk_score(model_id)
        
        return threat
    
    def _calculate_risk_score(self, likelihood, impact):
        """Calculate risk score based on likelihood and impact"""
        likelihood_scores = {'low': 1, 'medium': 2, 'high': 3}
        impact_scores = {'low': 1, 'medium': 2, 'high': 3}
        
        return likelihood_scores.get(likelihood, 2) * impact_scores.get(impact, 2)
    
    def _update_model_risk_score(self, model_id):
        """Update overall risk score for threat model"""
        model = self.threat_models[model_id]
        if model['threats']:
            total_risk = sum(t['risk_score'] for t in model['threats'])
            model['risk_score'] = total_risk / len(model['threats'])
        else:
            model['risk_score'] = 0
        
        model['last_updated'] = datetime.now().isoformat()
    
    def assess_risk(self, model_id):
        """Perform risk assessment on threat model"""
        if model_id not in self.threat_models:
            return {'error': 'Threat model not found'}
        
        model = self.threat_models[model_id]
        
        assessment = {
            'assessment_id': f"ASSESS_{int(datetime.now().timestamp())}",
            'model_id': model_id,
            'model_name': model['name'],
            'overall_risk_score': model['risk_score'],
            'risk_level': self._get_risk_level(model['risk_score']),
            'total_threats': len(model['threats']),
            'high_risk_threats': len([t for t in model['threats'] if t['risk_score'] >= 6]),
            'recommendations': self._generate_recommendations(model),
            'assessed_at': datetime.now().isoformat()
        }
        
        self.risk_assessments.append(assessment)
        return assessment
    
    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score >= 7: return 'CRITICAL'
        if score >= 5: return 'HIGH'
        if score >= 3: return 'MEDIUM'
        return 'LOW'
    
    def _generate_recommendations(self, model):
        """Generate risk mitigation recommendations"""
        recommendations = []
        
        high_risk_threats = [t for t in model['threats'] if t['risk_score'] >= 6]
        
        if high_risk_threats:
            recommendations.append('Prioritize mitigation of high-risk threats')
        
        if len(model['threats']) > 10:
            recommendations.append('Consider breaking down into smaller threat models')
        
        recommendations.append('Implement defense-in-depth strategy')
        recommendations.append('Regular security awareness training')
        
        return recommendations
    
    def get_modeling_statistics(self):
        """Get threat modeling statistics"""
        total_models = len(self.threat_models)
        total_threats = sum(len(m['threats']) for m in self.threat_models.values())
        
        risk_levels = defaultdict(int)
        for model in self.threat_models.values():
            risk_level = self._get_risk_level(model['risk_score'])
            risk_levels[risk_level] += 1
        
        return {
            'total_models': total_models,
            'total_threats': total_threats,
            'risk_distribution': dict(risk_levels),
            'assessments_performed': len(self.risk_assessments),
            'avg_threats_per_model': total_threats / max(total_models, 1)
        }

# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================

class PerformanceMonitor:
    """System performance monitoring and optimization"""
    
    def __init__(self):
        self.metrics = defaultdict(deque)
        self.alerts = []
        self.thresholds = {
            'cpu_usage': 80,
            'memory_usage': 85,
            'disk_usage': 90,
            'response_time': 5000,  # milliseconds
            'error_rate': 5  # percentage
        }
        self.monitoring_active = True
        
    def record_metric(self, metric_name, value, timestamp=None):
        """Record performance metric"""
        if not timestamp:
            timestamp = datetime.now()
        
        metric_entry = {
            'value': value,
            'timestamp': timestamp.isoformat(),
            'recorded_at': datetime.now().isoformat()
        }
        
        # Keep only last 1000 entries per metric
        if len(self.metrics[metric_name]) >= 1000:
            self.metrics[metric_name].popleft()
        
        self.metrics[metric_name].append(metric_entry)
        
        # Check thresholds
        self._check_threshold(metric_name, value)
        
        return metric_entry
    
    def _check_threshold(self, metric_name, value):
        """Check if metric exceeds threshold"""
        threshold = self.thresholds.get(metric_name)
        if threshold and value > threshold:
            alert = {
                'alert_id': f"PERF_{int(datetime.now().timestamp())}",
                'metric': metric_name,
                'value': value,
                'threshold': threshold,
                'severity': 'HIGH' if value > threshold * 1.2 else 'MEDIUM',
                'message': f'{metric_name} exceeded threshold: {value} > {threshold}',
                'timestamp': datetime.now().isoformat()
            }
            self.alerts.append(alert)
            return alert
        return None
    
    def get_system_health(self):
        """Get overall system health status"""
        health_score = 100
        issues = []
        
        # Check recent metrics
        for metric_name, threshold in self.thresholds.items():
            if metric_name in self.metrics and self.metrics[metric_name]:
                recent_value = self.metrics[metric_name][-1]['value']
                if recent_value > threshold:
                    health_score -= 20
                    issues.append(f'{metric_name}: {recent_value}')
        
        health_status = 'HEALTHY'
        if health_score < 60:
            health_status = 'CRITICAL'
        elif health_score < 80:
            health_status = 'WARNING'
        
        return {
            'health_score': max(health_score, 0),
            'status': health_status,
            'issues': issues,
            'last_check': datetime.now().isoformat(),
            'monitoring_active': self.monitoring_active
        }
    
    def get_metric_summary(self, metric_name, hours=24):
        """Get metric summary for specified time period"""
        if metric_name not in self.metrics:
            return {'error': 'Metric not found'}
        
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_metrics = [
            m for m in self.metrics[metric_name]
            if datetime.fromisoformat(m['timestamp']) > cutoff
        ]
        
        if not recent_metrics:
            return {'error': 'No recent data'}
        
        values = [m['value'] for m in recent_metrics]
        
        return {
            'metric': metric_name,
            'period_hours': hours,
            'data_points': len(values),
            'current_value': values[-1] if values else 0,
            'average': sum(values) / len(values),
            'minimum': min(values),
            'maximum': max(values),
            'threshold': self.thresholds.get(metric_name, 'N/A'),
            'threshold_breaches': len([v for v in values if v > self.thresholds.get(metric_name, float('inf'))])
        }
    
    def optimize_performance(self):
        """Suggest performance optimizations"""
        suggestions = []
        
        # Analyze metrics for optimization opportunities
        for metric_name in self.metrics:
            if metric_name in self.thresholds:
                recent_values = [m['value'] for m in list(self.metrics[metric_name])[-10:]]
                if recent_values:
                    avg_value = sum(recent_values) / len(recent_values)
                    threshold = self.thresholds[metric_name]
                    
                    if avg_value > threshold * 0.8:  # Near threshold
                        suggestions.append({
                            'metric': metric_name,
                            'current_avg': avg_value,
                            'threshold': threshold,
                            'suggestion': self._get_optimization_suggestion(metric_name),
                            'priority': 'HIGH' if avg_value > threshold else 'MEDIUM'
                        })
        
        return {
            'optimization_id': f"OPT_{int(datetime.now().timestamp())}",
            'suggestions': suggestions,
            'generated_at': datetime.now().isoformat()
        }
    
    def _get_optimization_suggestion(self, metric_name):
        """Get optimization suggestion for metric"""
        suggestions = {
            'cpu_usage': 'Consider scaling resources or optimizing CPU-intensive processes',
            'memory_usage': 'Review memory allocation and consider increasing available RAM',
            'disk_usage': 'Clean up old files or expand storage capacity',
            'response_time': 'Optimize database queries and implement caching',
            'error_rate': 'Review error logs and fix underlying issues'
        }
        return suggestions.get(metric_name, 'Monitor metric and investigate high values')
    
    def get_performance_statistics(self):
        """Get performance monitoring statistics"""
        total_metrics = sum(len(metrics) for metrics in self.metrics.values())
        active_alerts = len([a for a in self.alerts if 
                           datetime.now() - datetime.fromisoformat(a['timestamp']) < timedelta(hours=24)])
        
        return {
            'total_metrics_recorded': total_metrics,
            'active_metric_types': len(self.metrics),
            'active_alerts': active_alerts,
            'total_alerts': len(self.alerts),
            'monitoring_uptime': '99.9%',  # Simulated
            'last_optimization': datetime.now().isoformat()
        }