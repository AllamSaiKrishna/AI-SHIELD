import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'ai-shield-soc-secret-key-2026')
    DATABASE_PATH = os.path.join(BASE_DIR, 'instance', 'ai_shield.db')
    MODELS_DIR = os.path.join(BASE_DIR, 'models')
    MODEL_PATH = os.path.join(MODELS_DIR, 'ids_model.joblib')
    SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.joblib')
    META_PATH = os.path.join(MODELS_DIR, 'model_meta.json')
    DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')
    
    # IPS & Firewall Configuration
    PREVENTION_MODE = 'Alert Only'  # 'Disabled', 'Alert Only', 'Enabled'
    AUTO_BLOCK_SEVERITY = 'Critical' # Critical threats trigger block when enabled
    BLOCK_DURATION_MINUTES = 10
    
    # Safeguard Whitelist (Never block these IPs under any circumstances)
    WHITELIST_IPS = [
        '127.0.0.1',
        'localhost',
        '0.0.0.0',
        '192.168.1.1', # Common router/gateway
        '10.0.0.1',
        '172.16.0.1'
    ]
    
    # Permitted Lab CIDRs for active blocking
    ALLOWED_LAB_NETWORKS = ['192.168.1.0/24', '10.0.0.0/24', '172.16.0.0/24', '192.168.0.0/16']
    
    # Detection threshold (confidence score >= 0.70 triggers alert)
    DETECTION_THRESHOLD = 0.70
