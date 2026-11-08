"""Run with `python -m unittest discover -s tests` from backend/."""
import unittest
from app import app, normalize_local_url, ApiError


class FoundationTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json['scanner_ready'])

    def test_features_are_planned(self):
        response = self.client.get('/api/features')
        self.assertEqual(len(response.json['features']), 5)
        self.assertTrue(all(f['status'] == 'planned' for f in response.json['features']))

    def test_loopback_addresses_accepted(self):
        for url in ['http://localhost:5001', 'http://127.0.0.1:5002', 'http://[::1]:5003']:
            self.assertTrue(normalize_local_url(url))

    def test_external_addresses_rejected(self):
        for url in ['https://example.com', 'http://localhost.evil.com', 'file:///etc/passwd', 'http://user:pass@localhost:5001', 'http://10.0.0.8:5000', 'http://127.0.0.1:bad']:
            with self.subTest(url=url):
                with self.assertRaises(ApiError):
                    normalize_local_url(url)

    def test_targets_require_auth(self):
        response = self.client.get('/api/targets')
        self.assertIn(response.status_code, (401, 503))


if __name__ == '__main__':
    unittest.main()
