import joblib
import pandas as pd
from features import extract_features

# Load the trained model and feature columns
model = joblib.load('../ml/trained/phishing_model.pkl')
feature_columns = joblib.load('../ml/trained/feature_columns.pkl')

def get_reasons(features):
    reasons = []
    
    if features.get('suspecious_tld') == 1:
        reasons.append('Suspicious top-level domain (e.g. .tk, .ml, .ga)')
    if features.get('phish_hints') == 1:
        reasons.append('URL contains phishing keywords (login, verify, secure, account)')
    if features.get('prefix_suffix') == 1:
        reasons.append('Hyphen found in domain name')
    if features.get('nb_subdomains', 0) > 2:
        reasons.append('Excessive subdomains in URL')
    if features.get('shortening_service') == 1:
        reasons.append('URL shortening service detected')
    if features.get('nb_at', 0) > 0:
        reasons.append('@ symbol found in URL')
    if features.get('http_in_path') == 1:
        reasons.append('HTTP found in URL path')
    if features.get('ip') == 1:
        reasons.append('IP address used instead of domain name')
    if features.get('nb_dots', 0) > 4:
        reasons.append('Unusually high number of dots in URL')
    if features.get('length_url', 0) > 75:
        reasons.append('URL is unusually long')
    if features.get('punycode') == 1:
        reasons.append('Punycode detected in URL')
    if features.get('port') == 1:
        reasons.append('Non-standard port used in URL')

    return reasons if reasons else ['No specific indicators found']

def predict_url(url):
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
    reasons = get_reasons(features)
    
    # Return result
    return {
        'url': url,
        'prediction': 'phishing' if prediction == 1 else 'legitimate',
        'confidence': confidence_score,
        'reasons': reasons
    }