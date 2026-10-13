import os
import json
import joblib
from config import Config

class ModelLoader:
    _instance = None
    _model = None
    _scaler = None
    _metadata = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ModelLoader()
        return cls._instance

    def __init__(self):
        self.load()

    def load(self):
        try:
            if os.path.exists(Config.MODEL_PATH) and os.path.exists(Config.SCALER_PATH):
                self._model = joblib.load(Config.MODEL_PATH)
                self._scaler = joblib.load(Config.SCALER_PATH)
            else:
                self._model = None
                self._scaler = None
                
            if os.path.exists(Config.META_PATH):
                with open(Config.META_PATH, 'r') as f:
                    self._metadata = json.load(f)
            else:
                self._metadata = {
                    'model_name': 'AI-SHIELD Classifier (Unloaded)',
                    'classes': ['Normal', 'DoS / DDoS', 'PortScan', 'Brute Force', 'Web Attack'],
                    'features': ['duration', 'protocol', 'packet_count', 'byte_count', 'packet_rate', 'byte_rate', 'syn_ratio', 'ack_ratio', 'dst_host_count', 'serror_rate'],
                    'accuracy': 0.0,
                    'status': 'Not Loaded'
                }
        except Exception as e:
            print(f"[!] Error loading model artifacts: {e}")
            self._model = None
            self._scaler = None
            self._metadata = None

    @property
    def is_loaded(self):
        return self._model is not None and self._scaler is not None

    @property
    def model(self):
        return self._model

    @property
    def scaler(self):
        return self._scaler

    @property
    def metadata(self):
        return self._metadata or {}
