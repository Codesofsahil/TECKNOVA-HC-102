from datetime import datetime
import json
import re

class LogNormalizer:
    def __init__(self):
        self.schema = {
            'timestamp': None,
            'source_ip': None,
            'dest_ip': None,
            'source_port': None,
            'dest_port': None,
            'protocol': None,
            'event_type': None,
            'action': None,
            'severity': 'INFO',
            'user': None,
            'message': None,
            'raw_log': None
        }
    
    def normalize(self, log_entry, log_type='generic'):
        if log_type == 'syslog':
            return self._parse_syslog(log_entry)
        elif log_type == 'json':
            return self._parse_json(log_entry)
        elif log_type == 'windows':
            return self._parse_windows(log_entry)
        elif log_type == 'firewall':
            return self._parse_firewall(log_entry)
        return self._parse_generic(log_entry)
    
    def _parse_json(self, log):
        normalized = self.schema.copy()
        if isinstance(log, str):
            log = json.loads(log)
        normalized.update({
            'timestamp': log.get('timestamp', datetime.now().isoformat()),
            'source_ip': log.get('src_ip') or log.get('source_ip'),
            'dest_ip': log.get('dst_ip') or log.get('dest_ip'),
            'event_type': log.get('event_type'),
            'action': log.get('action'),
            'severity': log.get('severity', 'INFO'),
            'user': log.get('user'),
            'message': log.get('message'),
            'raw_log': str(log)
        })
        return normalized
    
    def _parse_syslog(self, log):
        normalized = self.schema.copy()
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)'
        match = re.match(pattern, log)
        if match:
            normalized['timestamp'] = match.group(1)
            normalized['source_ip'] = match.group(2)
            normalized['message'] = match.group(3)
        normalized['raw_log'] = log
        return normalized
    
    def _parse_windows(self, log):
        normalized = self.schema.copy()
        if 'EventID' in log:
            normalized['event_type'] = f"Windows_Event_{log.get('EventID')}"
        normalized['timestamp'] = log.get('TimeCreated', datetime.now().isoformat())
        normalized['user'] = log.get('User')
        normalized['message'] = log.get('Message')
        normalized['raw_log'] = str(log)
        return normalized
    
    def _parse_firewall(self, log):
        normalized = self.schema.copy()
        parts = log.split()
        if len(parts) >= 5:
            normalized['source_ip'] = parts[0] if self._is_ip(parts[0]) else None
            normalized['dest_ip'] = parts[2] if self._is_ip(parts[2]) else None
            normalized['action'] = parts[-1]
        normalized['raw_log'] = log
        return normalized
    
    def _parse_generic(self, log):
        normalized = self.schema.copy()
        normalized['timestamp'] = datetime.now().isoformat()
        normalized['message'] = str(log)
        normalized['raw_log'] = str(log)
        return normalized
    
    def _is_ip(self, text):
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(pattern, text))
