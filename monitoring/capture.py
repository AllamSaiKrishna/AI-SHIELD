import time
import random
import threading
import pandas as pd
from datetime import datetime
from detection.detector import Detector
from database.db import log_audit

class TrafficMonitor:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = TrafficMonitor()
        return cls._instance

    def __init__(self):
        self.is_running = False
        self.mode = 'simulation' # 'live', 'simulation', 'dataset_replay'
        self.worker_thread = None
        self.stop_event = threading.Event()
        self.packets_count = 0
        self.threats_count = 0
        self.selected_interface = "Default (Ethernet/WiFi)"

    def start(self, mode='simulation', interface="Default"):
        if self.is_running:
            return {'status': 'Already Running', 'mode': self.mode}
            
        self.mode = mode
        self.selected_interface = interface
        self.is_running = True
        self.stop_event.clear()
        
        self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.worker_thread.start()
        
        log_audit('MONITORING_START', f"Started traffic monitoring in {mode} mode on {interface}", status='SUCCESS')
        return {'status': 'Started', 'mode': self.mode, 'interface': self.selected_interface}

    def stop(self):
        if not self.is_running:
            return {'status': 'Already Stopped'}
            
        self.is_running = False
        self.stop_event.set()
        if self.worker_thread:
            self.worker_thread.join(timeout=2.0)
            
        log_audit('MONITORING_STOP', f"Traffic monitoring stopped. Processed {self.packets_count} flows.", status='SUCCESS')
        return {'status': 'Stopped', 'packets_processed': self.packets_count}

    def _generate_synthetic_flow(self):
        """
        Generates realistic network flow telemetry with occasional attack patterns.
        """
        attack_types = ['Normal', 'DoS / DDoS', 'PortScan', 'Brute Force', 'Web Attack']
        # 75% normal, 25% attacks during active simulation
        choice = random.choices(attack_types, weights=[0.75, 0.08, 0.07, 0.05, 0.05])[0]
        
        src_ip = f"192.168.1.{random.randint(10, 220)}"
        dst_ip = f"10.0.0.{random.randint(1, 30)}"
        
        if choice == 'Normal':
            duration = round(random.uniform(0.1, 4.0), 3)
            protocol = random.choice(['TCP', 'UDP'])
            packet_count = random.randint(5, 80)
            byte_count = packet_count * random.randint(100, 1200)
            packet_rate = round(packet_count / max(duration, 0.01), 2)
            byte_rate = round(byte_count / max(duration, 0.01), 2)
            syn_ratio = round(random.uniform(0.05, 0.15), 3)
            ack_ratio = round(random.uniform(0.7, 0.95), 3)
            dst_host_count = random.randint(1, 10)
            serror_rate = round(random.uniform(0.0, 0.04), 3)
            src_port = random.randint(2000, 65000)
            dst_port = random.choice([80, 443, 53, 8080])

        elif choice == 'DoS / DDoS':
            duration = round(random.uniform(0.5, 3.0), 3)
            protocol = random.choice(['TCP', 'UDP'])
            packet_count = random.randint(3000, 12000)
            byte_count = packet_count * random.randint(50, 400)
            packet_rate = round(packet_count / max(duration, 0.01), 2)
            byte_rate = round(byte_count / max(duration, 0.01), 2)
            syn_ratio = round(random.uniform(0.85, 0.99), 3)
            ack_ratio = round(random.uniform(0.0, 0.05), 3)
            dst_host_count = random.randint(1, 3)
            serror_rate = round(random.uniform(0.8, 0.99), 3)
            src_port = random.randint(1024, 65535)
            dst_port = 80

        elif choice == 'PortScan':
            duration = round(random.uniform(0.02, 0.3), 3)
            protocol = 'TCP'
            packet_count = random.randint(1, 4)
            byte_count = packet_count * 40
            packet_rate = round(packet_count / max(duration, 0.01), 2)
            byte_rate = round(byte_count / max(duration, 0.01), 2)
            syn_ratio = 1.0
            ack_ratio = 0.0
            dst_host_count = random.randint(80, 200)
            serror_rate = 1.0
            src_port = random.randint(30000, 60000)
            dst_port = random.randint(20, 1024)

        elif choice == 'Brute Force':
            duration = round(random.uniform(1.0, 5.0), 3)
            protocol = 'TCP'
            packet_count = random.randint(50, 250)
            byte_count = packet_count * random.randint(120, 280)
            packet_rate = round(packet_count / max(duration, 0.01), 2)
            byte_rate = round(byte_count / max(duration, 0.01), 2)
            syn_ratio = round(random.uniform(0.15, 0.25), 3)
            ack_ratio = round(random.uniform(0.45, 0.65), 3)
            dst_host_count = random.randint(1, 5)
            serror_rate = round(random.uniform(0.35, 0.6), 3)
            src_port = random.randint(4000, 50000)
            dst_port = random.choice([22, 3389, 21])

        else: # Web Attack
            duration = round(random.uniform(0.3, 2.0), 3)
            protocol = 'TCP'
            packet_count = random.randint(15, 60)
            byte_count = packet_count * random.randint(600, 1800)
            packet_rate = round(packet_count / max(duration, 0.01), 2)
            byte_rate = round(byte_count / max(duration, 0.01), 2)
            syn_ratio = round(random.uniform(0.1, 0.2), 3)
            ack_ratio = round(random.uniform(0.7, 0.9), 3)
            dst_host_count = random.randint(1, 8)
            serror_rate = round(random.uniform(0.2, 0.4), 3)
            src_port = random.randint(5000, 60000)
            dst_port = random.choice([80, 8080, 443])

        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'duration': duration,
            'byte_count': byte_count,
            'packet_count': packet_count,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'syn_ratio': syn_ratio,
            'ack_ratio': ack_ratio,
            'dst_host_count': dst_host_count,
            'serror_rate': serror_rate
        }

    def _run_loop(self):
        while not self.stop_event.is_set():
            try:
                flow = self._generate_synthetic_flow()
                res = Detector.classify_flow(flow, source_mode=self.mode)
                self.packets_count += 1
                if res.get('predicted_class') != 'Normal':
                    self.threats_count += 1
                
                # Pace simulation: 1-2 flows per second
                time.sleep(random.uniform(0.8, 1.6))
            except Exception as e:
                print(f"[!] Error in traffic monitor loop: {e}")
                time.sleep(1.0)

    def get_status(self):
        return {
            'running': self.is_running,
            'mode': self.mode,
            'interface': self.selected_interface,
            'packets_processed': self.packets_count,
            'threats_detected': self.threats_count
        }
