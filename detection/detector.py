import numpy as np
from datetime import datetime
from detection.model_loader import ModelLoader
from detection.feature_extractor import FeatureExtractor
from database.db import get_db_connection, log_audit, get_setting

SEVERITY_MAP = {
    'Normal': 'Low',
    'PortScan': 'Medium',
    'Brute Force': 'High',
    'Web Attack': 'High',
    'DoS / DDoS': 'Critical'
}

class Detector:
    @staticmethod
    def classify_flow(flow_data, source_mode='live'):
        """
        Classifies a single flow dictionary, stores record, creates alert if malicious,
        and optionally evaluates prevention rules.
        """
        loader = ModelLoader.get_instance()
        if not loader.is_loaded:
            return {
                'predicted_class': 'Unknown',
                'confidence': 0.0,
                'severity': 'Low',
                'status': 'Model Not Loaded'
            }
            
        # Extract and scale features
        X_scaled = FeatureExtractor.extract_and_scale(flow_data)
        
        # Predict class & confidence
        pred_class = loader.model.predict(X_scaled)[0]
        probabilities = loader.model.predict_proba(X_scaled)[0]
        class_idx = list(loader.model.classes_).index(pred_class)
        confidence = float(probabilities[class_idx])
        
        severity = SEVERITY_MAP.get(pred_class, 'Low')
        threshold = float(get_setting('detection_threshold', 0.70))
        
        src_ip = flow_data.get('src_ip', '192.168.1.100')
        dst_ip = flow_data.get('dst_ip', '10.0.0.5')
        protocol = flow_data.get('protocol', 'TCP')
        src_port = int(flow_data.get('src_port', 0))
        dst_port = int(flow_data.get('dst_port', 0))
        duration = float(flow_data.get('duration', 0.1))
        byte_count = int(flow_data.get('byte_count', 64))
        packet_count = int(flow_data.get('packet_count', 1))
        packet_rate = float(flow_data.get('packet_rate', packet_count / max(duration, 0.001)))
        
        # Save to database
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO traffic_records 
            (src_ip, dst_ip, protocol, src_port, dst_port, duration, byte_count, packet_count, packet_rate, predicted_class, confidence, source_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (src_ip, dst_ip, str(protocol), src_port, dst_port, duration, byte_count, packet_count, packet_rate, pred_class, confidence, source_mode))
        
        traffic_id = cur.lastrowid
        alert_id = None
        action_taken = 'Logged'
        
        # Create alert if malicious & passes threshold
        if pred_class != 'Normal' and confidence >= threshold:
            details = f"Detected {pred_class} with {confidence*100:.1f}% confidence. Source: {src_ip}:{src_port} -> Target: {dst_ip}:{dst_port}"
            cur.execute("""
                INSERT INTO alerts (traffic_id, threat_type, severity, status, details, src_ip, dst_ip, confidence)
                VALUES (?, ?, ?, 'New', ?, ?, ?, ?)
            """, (traffic_id, pred_class, severity, details, src_ip, dst_ip, confidence))
            alert_id = cur.lastrowid
            
            # Check IPS prevention policy
            from prevention.policy import PreventionPolicy
            action_taken = PreventionPolicy.evaluate_and_respond(src_ip, pred_class, severity, confidence)
            
        conn.commit()
        conn.close()
        
        return {
            'traffic_id': traffic_id,
            'alert_id': alert_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'predicted_class': pred_class,
            'confidence': round(confidence, 4),
            'severity': severity,
            'action_taken': action_taken
        }
