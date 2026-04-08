import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app import app
from features import extract_features

class TestFeatureExtraction(unittest.TestCase):

    def test_phishing_url_features(self):
        url = "http://paypal-secure-login.tk/verify"
        features = extract_features(url)
        self.assertEqual(features['suspecious_tld'], 1)
        self.assertEqual(features['phish_hints'], 1)
        self.assertEqual(features['prefix_suffix'], 1)

    def test_legitimate_url_features(self):
        url = "https://www.google.com"
        features = extract_features(url)
        self.assertEqual(features['https_token'], 1)
        self.assertEqual(features['suspecious_tld'], 0)

class TestAPI(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_home_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)

    def test_awareness_page(self):
        response = self.app.get('/awareness')
        self.assertEqual(response.status_code, 200)

    def test_404_page(self):
        response = self.app.get('/randompage')
        self.assertEqual(response.status_code, 404)

    def test_analyze_phishing(self):
        response = self.app.post('/analyze',
            json={'url': 'http://paypal-secure-login.tk/verify'})
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn('prediction', data)
        self.assertIn('confidence', data)
        self.assertIn('reasons', data)

    def test_analyze_legitimate(self):
        response = self.app.post('/analyze',
            json={'url': 'https://www.google.com'})
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['prediction'], 'legitimate')

    def test_analyze_no_url(self):
        response = self.app.post('/analyze', json={})
        self.assertEqual(response.status_code, 400)

if __name__ == '__main__':
    unittest.main()