import joblib
import pandas as pd
from features import extract_features

# Load the trained model and feature columns
model = joblib.load('../ml/trained/phishing_model.pkl')
feature_columns = joblib.load('../ml/trained/feature_columns.pkl')

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
    
    # Return result
    return {
        'url': url,
        'prediction': 'phishing' if prediction == 1 else 'legitimate',
        'confidence': confidence_score
    }