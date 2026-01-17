from datetime import datetime

class PlaybookEngine:
    def __init__(self):
        self.playbooks = {}
        self.executions = []
        self._load_default_playbooks()
    
    def _load_default_playbooks(self):
        self.playbooks = {
            'brute_force_response': {
                'name': 'Brute Force Attack Response',
                'steps': [
                    {'action': 'block_ip', 'params': {'duration': 3600}},
                    {'action': 'notify_soc', 'params': {'priority': 'high'}},
                    {'action': 'create_ticket', 'params': {}},
                    {'action': 'enrich_threat_intel', 'params': {}}
                ]
            },
            'malware_detected': {
                'name': 'Malware Detection Response',
                'steps': [
                    {'action': 'isolate_host', 'params': {}},
                    {'action': 'notify_soc', 'params': {'priority': 'critical'}},
                    {'action': 'start_forensics', 'params': {}}
                ]
            }
        }
    
    def execute_playbook(self, playbook_name, context):
        if playbook_name not in self.playbooks:
            return {'error': 'Playbook not found'}
        
        playbook = self.playbooks[playbook_name]
        execution_id = f"EXEC_{int(datetime.now().timestamp())}"
        
        execution = {
            'execution_id': execution_id,
            'playbook_name': playbook_name,
            'started_at': datetime.now().isoformat(),
            'steps_completed': [],
            'status': 'completed'
        }
        
        for step in playbook['steps']:
            result = self._execute_step(step, context)
            execution['steps_completed'].append({
                'action': step['action'],
                'result': result,
                'timestamp': datetime.now().isoformat()
            })
        
        self.executions.append(execution)
        return execution
    
    def _execute_step(self, step, context):
        action = step['action']
        return {'status': 'success', 'action': action}
    
    def list_playbooks(self):
        return [{'name': name, 'description': pb['name']} for name, pb in self.playbooks.items()]
