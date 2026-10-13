import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app

class TestViewRoutes(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_pages_render(self):
        pages = [
            '/',
            '/monitoring',
            '/detection',
            '/alerts',
            '/prevention',
            '/reports',
            '/model',
            '/settings'
        ]
        for p in pages:
            res = self.client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} returned status {res.status_code}")
            self.assertIn(b'AI-SHIELD', res.data, f"Page {p} missing brand tag")

if __name__ == '__main__':
    unittest.main()
