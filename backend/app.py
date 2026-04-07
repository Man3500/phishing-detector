from flask import Flask, request, jsonify, render_template
from predictor import predict_url

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

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

if __name__ == '__main__':
    app.run(debug=True)

