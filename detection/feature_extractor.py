import numpy as np
import pandas as pd
from detection.model_loader import ModelLoader

class FeatureExtractor:
    FEATURE_NAMES = [
        'duration', 'protocol', 'packet_count', 'byte_count', 
        'packet_rate', 'byte_rate', 'syn_ratio', 'ack_ratio', 
        'dst_host_count', 'serror_rate'
    ]

    @staticmethod
    def protocol_to_num(proto):
        if isinstance(proto, (int, float)):
            return float(proto)
        proto_str = str(proto).upper().strip()
        if 'TCP' in proto_str:
            return 6.0
        elif 'UDP' in proto_str:
            return 17.0
        elif 'ICMP' in proto_str:
            return 1.0
        return 6.0

    @classmethod
    def extract_from_dict(cls, data):
        """
        Extracts and aligns 10 flow features from raw dictionary.
        """
        duration = float(data.get('duration', 0.1))
        packet_count = float(data.get('packet_count', 1))
        byte_count = float(data.get('byte_count', 64))
        
        # Calculate rates if not provided
        packet_rate = float(data.get('packet_rate', packet_count / max(duration, 0.001)))
        byte_rate = float(data.get('byte_rate', byte_count / max(duration, 0.001)))
        
        protocol = cls.protocol_to_num(data.get('protocol', 6))
        syn_ratio = float(data.get('syn_ratio', 0.1))
        ack_ratio = float(data.get('ack_ratio', 0.8))
        dst_host_count = float(data.get('dst_host_count', 1))
        serror_rate = float(data.get('serror_rate', 0.0))

        raw_vector = [
            duration, protocol, packet_count, byte_count,
            packet_rate, byte_rate, syn_ratio, ack_ratio,
            dst_host_count, serror_rate
        ]
        
        return np.array(raw_vector).reshape(1, -1)

    @classmethod
    def extract_and_scale(cls, data):
        """
        Extracts features and applies the fitted StandardScaler.
        """
        vector = cls.extract_from_dict(data)
        loader = ModelLoader.get_instance()
        if loader.scaler is not None:
            df_vec = pd.DataFrame(vector, columns=cls.FEATURE_NAMES)
            return loader.scaler.transform(df_vec)
        return vector

    @classmethod
    def extract_from_df(cls, df):
        """
        Extracts feature matrix from a pandas DataFrame.
        """
        df_copy = df.copy()
        for col in cls.FEATURE_NAMES:
            if col not in df_copy.columns:
                if col == 'duration':
                    df_copy[col] = 0.5
                elif col == 'protocol':
                    df_copy[col] = 6.0
                elif col == 'packet_rate' and 'packet_count' in df_copy.columns:
                    df_copy[col] = df_copy['packet_count'] / 0.5
                elif col == 'byte_rate' and 'byte_count' in df_copy.columns:
                    df_copy[col] = df_copy['byte_count'] / 0.5
                else:
                    df_copy[col] = 0.0
                    
        # Ensure protocol is numeric
        df_copy['protocol'] = df_copy['protocol'].apply(cls.protocol_to_num)
        
        X = df_copy[cls.FEATURE_NAMES].fillna(0).astype(float)
        loader = ModelLoader.get_instance()
        if loader.scaler is not None:
            return loader.scaler.transform(X)
        return X.values
