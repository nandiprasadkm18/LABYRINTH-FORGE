from flask import Flask, request, render_template_string, jsonify, Response
import sqlite3
import os
import subprocess
import ipaddress
import logging
import time
from functools import wraps
from werkzeug.security import check_password_hash
import base64
import binascii

# --- SURGICAL SECURITY CONFIGURATION ---
BASE_DIR = os.path.abspath("/var/lib/app/data")
MAX_USERNAME_LEN = 32
MAX_PASSWORD_LEN = 128
MAX_QUERY_LEN = 100
MAX_FILENAME_LEN = 255
MAX_IP_LEN = 45
MAX_CMD_LEN = 100
MAX_CONTENT_LENGTH = 4 * 1024  # Surgical 4KB Limit

# 1. Enforce Env Secrets (CWE-798)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
SHIELD_API_TOKEN = os.environ.get("SHIELD_API_TOKEN")
if not SECRET_KEY or not SHIELD_API_TOKEN:
    raise RuntimeError("CRITICAL: Missing FLASK_SECRET_KEY or SHIELD_API_TOKEN")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Setup Secure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory rate limiting
login_attempts = {}

# --- SURGICAL UTILITIES & GUARDS ---

def secure_b64_decode(data):
    try:
        if not data or len(data) > 4096:
            return None
        # Enforce structural validation
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        logging.error("Invalid base64 structural validation failure")
        return None

def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-Shield-Token')
        if token != SHIELD_API_TOKEN:
            return jsonify({"error": "Unauthorized Access"}), 401
        return f(*args, **kwargs)
    return decorated_function

def secure_headers(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if isinstance(response, str):
            response = Response(response)
        response.headers.update({
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000'
        })
        return response
    return decorated_function

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Internal Event: {str(e)}")
    return jsonify({"error": "Security Event Triggered"}), 500

# --- REMEDIATED ENDPOINTS ---

@app.route('/login', methods=['POST'])
@secure_headers
def login():
    ip = request.remote_addr
    now = time.time()
    attempts, last_time = login_attempts.get(ip, (0, now))
    if attempts >= 3 and now - last_time < 60:
        return jsonify({"error": "Too many attempts"}), 429
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if not username or len(username) > MAX_USERNAME_LEN or not password or len(password) > MAX_PASSWORD_LEN:
        return jsonify({"error": "Invalid Input"}), 400

    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if row and check_password_hash(row[0], password):
                login_attempts[ip] = (0, now)
                return jsonify({"status": "Authenticated"}), 200
    except sqlite3.Error:
        pass
    
    login_attempts[ip] = (attempts + 1, now)
    return jsonify({"error": "Invalid Credentials"}), 401

@app.route('/ping')
@secure_headers
def ping():
    ip = request.args.get('ip', '')
    try:
        # Surgical Command Hardening: 3s timeout + check=True + IP validation
        ip_obj = ipaddress.ip_address(ip)
        subprocess.run(['ping', '-c', '1', str(ip_obj)], check=True, shell=False, timeout=3)
        return jsonify({"status": f"Host {ip_obj} verified"}), 200
    except (ValueError, subprocess.SubprocessError):
        return jsonify({"error": "Audit Failed"}), 400

@app.route('/read')
@secure_headers
def read_file():
    filename = request.args.get('file', '')
    if not filename or len(filename) > MAX_FILENAME_LEN:
        return jsonify({"error": "Invalid filename"}), 400

    # Surgical Path Hardening
    safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        return jsonify({"error": "Forbidden"}), 403
    try:
        with open(safe_path, 'r') as f:
            return f.read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Not Found"}), 404

@app.route('/b64', methods=['POST'])
@secure_headers
def b64_process():
    # Surgical Base64 Validation
    data = request.form.get('data', '')
    decoded = secure_b64_decode(data)
    if decoded is None:
        return jsonify({"error": "Invalid base64 input"}), 400
    return jsonify({"status": "processed"}), 200

@app.route('/admin')
@secure_headers
def admin():
    return jsonify({"error": "Forbidden"}), 403

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=8000)
