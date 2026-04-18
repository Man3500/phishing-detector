# Phishing Detector

Small Flask-based phishing URL detector. This repository includes a trained scikit-learn model (in `ml/trained/`) and a Flask app in `backend/` that exposes a web UI under `frontend/`.

Quick start
1. Create a virtual environment and activate it (macOS / zsh):

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

3. Run the Flask app (from project root):

```bash
export FLASK_APP=backend/app.py
export FLASK_ENV=development
flask run
```

Run tests

```bash
python -m pytest -q
```

Notes
- The trained model and feature column files are expected in `ml/trained/` (committed). If you retrain the model, overwrite those files.
- If you plan to deploy, consider configuring environment variables for model paths and adding a CI workflow.
