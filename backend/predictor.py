import joblib
import re
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
from features import extract_features

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'reddit.com',
    'netflix.com', 'microsoft.com', 'apple.com', 'github.com', 'yahoo.com',
    'paypal.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    'outlook.com', 'gmail.com', 'whatsapp.com'
}

# Resolve model and feature paths relative to the project root (file's parent parent)
BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / 'ml' / 'trained' / 'phishing_model.pkl'
FEATURES_PATH = BASE_DIR / 'ml' / 'trained' / 'feature_columns.pkl'

# Load the trained model and feature columns
model = joblib.load(str(MODEL_PATH))
feature_columns = joblib.load(str(FEATURES_PATH))

def get_reasons(features, url):
    reasons = []
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()

    if features.get('suspecious_tld') == 1:
        tld = '.' + hostname.split('.')[-1]
        reasons.append(f'Suspicious TLD detected: {tld}')
    if features.get('phish_hints') == 1:
        match = re.search(r'(login|signin|verify|update|secure|account|password|bank)', url, re.IGNORECASE)
        reasons.append(f'Phishing keyword found in URL: "{match.group()}"')
    if features.get('prefix_suffix') == 1:
        reasons.append(f'Hyphen found in domain: {hostname}')
    if features.get('nb_subdomains', 0) > 2:
        reasons.append(f'Excessive subdomains: {hostname}')
    if features.get('shortening_service') == 1:
        reasons.append(f'URL shortening service detected: {hostname}')
    if features.get('nb_at', 0) > 0:
        reasons.append(f'@ symbol found in URL — may be used to disguise the real destination')
    if features.get('http_in_path') == 1:
        reasons.append(f'Embedded HTTP found in URL path — possible redirect trick')
    if features.get('ip') == 1:
        reasons.append(f'IP address used instead of domain name: {hostname}')
    if features.get('nb_dots', 0) > 4:
        reasons.append(f'Unusually high number of dots in URL ({features["nb_dots"]})')
    if features.get('length_url', 0) > 75:
        reasons.append(f'URL is unusually long ({features["length_url"]} characters)')
    if features.get('punycode') == 1:
        reasons.append(f'Punycode encoding detected in domain: {hostname}')
    if features.get('port') == 1:
        reasons.append(f'Non-standard port used: {parsed.port}')
    if features.get('has_cyrillic') == 1:
        reasons.append(f'Cyrillic characters detected in domain — may be impersonating a legitimate site')
    if features.get('mixed_scripts') == 1:
        reasons.append(f'Mixed character scripts detected in domain — classic homograph attack pattern')
    if features.get('typosquatting') == 1:
        reasons.append(f'Domain appears to impersonate a known brand: {hostname}')
    if features.get('encoding_obfuscation') == 1:
        reasons.append(f'URL encoding obfuscation detected — characters may be hidden')
    if features.get('brand_in_subdomain') == 1:
        reasons.append(f'Known brand name found in subdomain — possible impersonation: {hostname}')

    return reasons if reasons else ['No specific indicators found']

def predict_url(url):
    # Check against trusted domains first
    hostname = urlparse(url).netloc.lower().replace('www.', '')
    if hostname in TRUSTED_DOMAINS:
        return {
            'url': url,
            'prediction': 'legitimate',
            'confidence': 99.0,
            'reasons': ['Domain is a known trusted website']
        }

    # Extract features from the URL
    features = extract_features(url)
    
    # Convert to dataframe with only the columns the model expects
    df = pd.DataFrame([features])[feature_columns]
    
    # Make prediction
    prediction = model.predict(df)[0]
    confidence = model.predict_proba(df)[0]
    
    # Get confidence score
    confidence_score = round(max(confidence) * 100, 2)
    
    # Get reasons
    reasons = get_reasons(features, url)
    
    # Return result
    return {
        'url': url,
        'prediction': 'phishing' if prediction == 1 else 'legitimate',
        'confidence': confidence_score,
        'reasons': reasons
    }