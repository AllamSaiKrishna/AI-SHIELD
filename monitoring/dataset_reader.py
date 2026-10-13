import os
import numpy as np
import pandas as pd
from detection.feature_extractor import FeatureExtractor
from detection.detector import Detector
from detection.model_loader import ModelLoader
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

class DatasetReader:
    @staticmethod
    def validate_csv(filepath):
        """
        Validates CSV file for minimum flow columns and returns schema details.
        """
        try:
            df = pd.read_csv(filepath)
            cols = list(df.columns)
            row_count = len(df)
            has_label = 'label' in [c.lower() for c in cols]
            
            # Check feature overlap
            req_features = FeatureExtractor.FEATURE_NAMES
            matched_features = [f for f in req_features if f in cols]
            
            return {
                'valid': True,
                'row_count': row_count,
                'columns': cols,
                'has_label': has_label,
                'matched_features': matched_features,
                'missing_features': [f for f in req_features if f not in cols]
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}

    @staticmethod
    def process_csv_batch(filepath, max_rows=300):
        """
        Processes a dataset file in batch, runs inference, and calculates metrics if labels exist.
        """
        df = pd.read_csv(filepath)
        if len(df) > max_rows:
            df = df.head(max_rows)
            
        loader = ModelLoader.get_instance()
        if not loader.is_loaded:
            return {'error': 'AI Model not loaded'}
            
        X_scaled = FeatureExtractor.extract_from_df(df)
        preds = loader.model.predict(X_scaled)
        probs = loader.model.predict_proba(X_scaled)
        
        results = []
        has_label = 'label' in df.columns
        actuals = df['label'].tolist() if has_label else None
        
        attack_counts = {}
        for i, row in df.iterrows():
            pred = preds[i]
            prob = float(np.max(probs[i]))
            attack_counts[pred] = attack_counts.get(pred, 0) + 1
            
            res_item = {
                'index': int(i),
                'src_ip': str(row.get('src_ip', f"192.168.1.{100 + (i%50)}")),
                'dst_ip': str(row.get('dst_ip', "10.0.0.15")),
                'protocol': str(row.get('protocol', 'TCP')),
                'predicted_class': pred,
                'confidence': round(prob, 4),
                'actual_label': str(actuals[i]) if has_label else 'N/A'
            }
            results.append(res_item)
            
        metrics = None
        if has_label:
            acc = accuracy_score(actuals, preds)
            prec = precision_score(actuals, preds, average='weighted', zero_division=0)
            rec = recall_score(actuals, preds, average='weighted', zero_division=0)
            f1 = f1_score(actuals, preds, average='weighted', zero_division=0)
            metrics = {
                'accuracy': round(acc, 4),
                'precision': round(prec, 4),
                'recall': round(rec, 4),
                'f1_score': round(f1, 4)
            }
            
        return {
            'total_processed': len(results),
            'attack_counts': attack_counts,
            'records': results[:50], # Return top 50 for table display
            'metrics': metrics
        }
