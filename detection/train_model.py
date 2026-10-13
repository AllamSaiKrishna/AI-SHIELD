import os
import json
import numpy as np
import pandas as pd
from datetime import datetime
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(DATASETS_DIR, exist_ok=True)

FEATURES = [
    'duration', 'protocol', 'packet_count', 'byte_count', 
    'packet_rate', 'byte_rate', 'syn_ratio', 'ack_ratio', 
    'dst_host_count', 'serror_rate'
]

CLASSES = ['Normal', 'DoS / DDoS', 'PortScan', 'Brute Force', 'Web Attack']

def generate_synthetic_flow_dataset(n_samples=5000):
    np.random.seed(42)
    data = []
    labels = []
    
    samples_per_class = n_samples // len(CLASSES)
    
    # 1. Normal Traffic
    for _ in range(samples_per_class):
        duration = np.random.exponential(scale=2.5) + 0.1
        protocol = np.random.choice([6, 17], p=[0.75, 0.25]) # TCP or UDP
        packet_count = np.random.randint(5, 120)
        byte_count = packet_count * np.random.randint(64, 1400)
        packet_rate = packet_count / max(duration, 0.01)
        byte_rate = byte_count / max(duration, 0.01)
        syn_ratio = np.random.uniform(0.05, 0.2)
        ack_ratio = np.random.uniform(0.6, 0.95)
        dst_host_count = np.random.randint(1, 20)
        serror_rate = np.random.uniform(0.0, 0.05)
        
        data.append([duration, protocol, packet_count, byte_count, packet_rate, byte_rate, syn_ratio, ack_ratio, dst_host_count, serror_rate])
        labels.append('Normal')
        
    # 2. DoS / DDoS Traffic (High volume, high packet rate, abnormal SYN ratio)
    for _ in range(samples_per_class):
        duration = np.random.uniform(0.5, 10.0)
        protocol = np.random.choice([6, 17, 1], p=[0.6, 0.3, 0.1])
        packet_count = np.random.randint(1500, 15000)
        byte_count = packet_count * np.random.randint(40, 500)
        packet_rate = packet_count / max(duration, 0.01)
        byte_rate = byte_count / max(duration, 0.01)
        syn_ratio = np.random.uniform(0.7, 0.99)
        ack_ratio = np.random.uniform(0.0, 0.15)
        dst_host_count = np.random.randint(1, 5) # Focused target
        serror_rate = np.random.uniform(0.6, 0.99)
        
        data.append([duration, protocol, packet_count, byte_count, packet_rate, byte_rate, syn_ratio, ack_ratio, dst_host_count, serror_rate])
        labels.append('DoS / DDoS')

    # 3. PortScan Traffic (Rapid sequential port probing, zero payload, high error)
    for _ in range(samples_per_class):
        duration = np.random.uniform(0.01, 0.8)
        protocol = 6 # TCP SYN scan
        packet_count = np.random.randint(1, 5)
        byte_count = packet_count * np.random.randint(40, 60)
        packet_rate = packet_count / max(duration, 0.01)
        byte_rate = byte_count / max(duration, 0.01)
        syn_ratio = np.random.uniform(0.85, 1.0)
        ack_ratio = np.random.uniform(0.0, 0.05)
        dst_host_count = np.random.randint(50, 255) # Scanning many hosts/ports
        serror_rate = np.random.uniform(0.75, 1.0)
        
        data.append([duration, protocol, packet_count, byte_count, packet_rate, byte_rate, syn_ratio, ack_ratio, dst_host_count, serror_rate])
        labels.append('PortScan')

    # 4. Brute Force Traffic (Repeated auth attempts on service ports)
    for _ in range(samples_per_class):
        duration = np.random.uniform(1.0, 8.0)
        protocol = 6 # TCP
        packet_count = np.random.randint(40, 300)
        byte_count = packet_count * np.random.randint(100, 300)
        packet_rate = packet_count / max(duration, 0.01)
        byte_rate = byte_count / max(duration, 0.01)
        syn_ratio = np.random.uniform(0.1, 0.3)
        ack_ratio = np.random.uniform(0.4, 0.7)
        dst_host_count = np.random.randint(1, 10)
        serror_rate = np.random.uniform(0.3, 0.65)
        
        data.append([duration, protocol, packet_count, byte_count, packet_rate, byte_rate, syn_ratio, ack_ratio, dst_host_count, serror_rate])
        labels.append('Brute Force')

    # 5. Web Attack (SQLi / XSS / LFI payloads, HTTP/HTTPS patterns)
    for _ in range(samples_per_class):
        duration = np.random.uniform(0.2, 3.5)
        protocol = 6 # TCP
        packet_count = np.random.randint(10, 80)
        byte_count = packet_count * np.random.randint(450, 2200) # Large crafted payloads
        packet_rate = packet_count / max(duration, 0.01)
        byte_rate = byte_count / max(duration, 0.01)
        syn_ratio = np.random.uniform(0.05, 0.25)
        ack_ratio = np.random.uniform(0.65, 0.95)
        dst_host_count = np.random.randint(1, 15)
        serror_rate = np.random.uniform(0.15, 0.45) # 4xx / 5xx error responses
        
        data.append([duration, protocol, packet_count, byte_count, packet_rate, byte_rate, syn_ratio, ack_ratio, dst_host_count, serror_rate])
        labels.append('Web Attack')
        
    df = pd.DataFrame(data, columns=FEATURES)
    df['label'] = labels
    return df

def train_and_save():
    print("[*] Generating benchmark network flow training dataset...")
    df = generate_synthetic_flow_dataset(n_samples=6000)
    
    # Save benchmark evaluation datasets
    test_suite = df.sample(frac=0.3, random_state=42)
    test_suite.to_csv(os.path.join(DATASETS_DIR, 'test_attack_suite.csv'), index=False)
    
    # Sample unlabelled traffic for live playback
    sample_traffic = df.sample(n=100, random_state=123).drop(columns=['label'])
    # Add simulated IP columns for visualization
    sample_traffic.insert(0, 'src_ip', [f"192.168.1.{np.random.randint(10, 250)}" for _ in range(100)])
    sample_traffic.insert(1, 'dst_ip', [f"10.0.0.{np.random.randint(1, 50)}" for _ in range(100)])
    sample_traffic.insert(2, 'src_port', [np.random.randint(1024, 65535) for _ in range(100)])
    sample_traffic.insert(3, 'dst_port', [np.random.choice([80, 443, 22, 3389, 53, 8080]) for _ in range(100)])
    sample_traffic.to_csv(os.path.join(DATASETS_DIR, 'sample_traffic.csv'), index=False)
    
    X = df[FEATURES]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    print("[*] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("[*] Training Random Forest Threat Classifier...")
    model = RandomForestClassifier(n_estimators=120, max_depth=16, random_state=42, n_jobs=-1)
    model.fit(X_train_scaled, y_train)
    
    y_pred = model.predict(X_test_scaled)
    
    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, average='weighted')
    rec = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')
    cm = confusion_matrix(y_test, y_pred, labels=CLASSES).tolist()
    
    print(f"[+] Model Performance:")
    print(f"    - Accuracy:  {acc * 100:.2f}%")
    print(f"    - Precision: {prec * 100:.2f}%")
    print(f"    - Recall:    {rec * 100:.2f}%")
    print(f"    - F1 Score:  {f1 * 100:.2f}%")
    
    # Feature Importances
    importances = dict(zip(FEATURES, [round(float(v), 4) for v in model.feature_importances_]))
    
    metadata = {
        'model_name': 'AI-SHIELD Random Forest Multi-Threat Classifier',
        'version': '2.4.0',
        'classes': CLASSES,
        'features': FEATURES,
        'accuracy': round(acc, 4),
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1_score': round(f1, 4),
        'confusion_matrix': cm,
        'feature_importances': importances,
        'trained_at': datetime.now().isoformat(),
        'n_estimators': 120,
        'training_samples': len(X_train)
    }
    
    joblib.dump(model, os.path.join(MODELS_DIR, 'ids_model.joblib'))
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.joblib'))
    with open(os.path.join(MODELS_DIR, 'model_meta.json'), 'w') as f:
        json.dump(metadata, f, indent=4)
        
    print("[+] Model artifacts and evaluation datasets saved successfully!")

if __name__ == '__main__':
    train_and_save()
