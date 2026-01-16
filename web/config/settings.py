import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'soc-platform-secret-key-2024'
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    LOGS_DIR = os.path.join(DATA_DIR, 'logs')
    RULES_DIR = os.path.join(DATA_DIR, 'rules')
    
    # Alert thresholds
    ALERT_SEVERITY = {
        'CRITICAL': 5,
        'HIGH': 4,
        'MEDIUM': 3,
        'LOW': 2,
        'INFO': 1
    }
    
    # Correlation settings
    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW = 300  # 5 minutes
    PORT_SCAN_THRESHOLD = 10
    PORT_SCAN_WINDOW = 60
    
    # ML settings
    ANOMALY_THRESHOLD = 2.5  # Z-score threshold
    
    # Threat Intel
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
