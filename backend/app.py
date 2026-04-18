from flask import Flask, request, jsonify, render_template
from predictor import predict_url
from pathlib import Path
import sqlite3
import os

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

# Database setup
DB_PATH = Path(__file__).resolve().parent.parent / 'database' / 'feedback.db'

def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            correct INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/awareness')
def awareness():
    return render_template('awareness.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    result = predict_url(url)
    return jsonify(result)

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.get_json()
    url = data.get('url')
    prediction = data.get('prediction')
    correct = data.get('correct')

    if not all([url, prediction, correct is not None]):
        return jsonify({'error': 'Missing data'}), 400

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute('INSERT INTO feedback (url, prediction, correct) VALUES (?, ?, ?)',
              (url, prediction, int(correct)))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Feedback saved. Thank you!'})

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)