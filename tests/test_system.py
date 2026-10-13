import unittest
import json
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from database.db import init_db

class TestAIShieldSystem(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = app.test_client()

    def test_01_health(self):
        res = self.client.get('/api/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'HEALTHY')
        self.assertTrue(data['model_loaded'])

    def test_02_status(self):
        res = self.client.get('/api/status')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'Online')
        self.assertTrue(data['model_loaded'])

    def test_03_metrics(self):
        res = self.client.get('/api/metrics')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('total_flows', data)
        self.assertIn('breakdown', data)

    def test_04_single_flow_prediction(self):
        payload = {
            'src_ip': '192.168.1.185',
            'protocol': 'TCP',
            'duration': 2.4,
            'packet_count': 8500,
            'byte_count': 520000,
            'syn_ratio': 0.94,
            'ack_ratio': 0.02,
            'serror_rate': 0.88,
            'dst_host_count': 3
        }
        res = self.client.post('/api/detection/predict', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('predicted_class', data)
        self.assertGreater(data['confidence'], 0.5)

    def test_05_dataset_batch_analyze(self):
        res = self.client.post('/api/dataset/analyze')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn('total_processed', data)
        self.assertIn('metrics', data)
        self.assertGreater(data['metrics']['accuracy'], 0.9)

    def test_06_prevention_lifecycle(self):
        # 1. Check status
        res = self.client.get('/api/prevention/status')
        self.assertEqual(res.status_code, 200)
        
        # 2. Block test IP
        block_res = self.client.post('/api/prevention/block', json={
            'ip': '192.168.1.222',
            'duration': 5,
            'reason': 'Automated Test Block'
        })
        self.assertEqual(block_res.status_code, 200)
        self.assertTrue(block_res.get_json()['success'])
        
        # 3. Whitelist protection check
        reject_res = self.client.post('/api/prevention/block', json={
            'ip': '127.0.0.1',
            'duration': 5,
            'reason': 'Loopback test'
        })
        self.assertFalse(reject_res.get_json()['success'])
        
        # 4. Unblock test IP
        unblock_res = self.client.post('/api/prevention/unblock', json={'ip': '192.168.1.222'})
        self.assertEqual(unblock_res.status_code, 200)

    def test_07_reports_export(self):
        res = self.client.get('/api/reports/export?type=audit')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.content_type, 'text/csv; charset=utf-8')

if __name__ == '__main__':
    unittest.main()
