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
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB Limit

# 1. Enforce SECRET_KEY (CWE-798)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
SHIELD_API_TOKEN = os.environ.get('SHIELD_API_TOKEN')
if not SECRET_KEY or not SHIELD_API_TOKEN:
    raise RuntimeError("Missing configuration: FLASK_SECRET_KEY or SHIELD_API_TOKEN environment variable is required.")

app = Flask(__name__)

# 5. Add request size limit
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Setup Secure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# In-memory rate limiting for login
login_attempts = {}

# --- SECURE UTILITIES & GUARDS ---

def secure_headers(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = f(*args, **kwargs)
        if isinstance(response, str):
            response = Response(response)
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response
    return decorated_function

def validate_input(text, max_len, field_name):
    if not text or len(text) > max_len:
        logging.warning(f"Validation Failure: {field_name} violation.")
        return False
    return True

def secure_b64_decode(data):
    try:
        return base64.b64decode(data)
    except binascii.Error:
        logging.error("Invalid base64 decoding")
        return None

def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-Shield-Token')
        if token != SHIELD_API_TOKEN:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.errorhandler(Exception)
def handle_exception(e):
    # 4. Secure logging without exposing details
    logging.error(f"Internal Error Trace: {str(e)}")
    return jsonify({"error": "An internal security event occurred."}), 500

# --- REMEDIATED ENDPOINTS ---

@app.route('/login', methods=['POST'])
@secure_headers
@require_token
def login():
    # 6. Basic rate limiting
    ip = request.remote_addr
    now = time.time()
    if ip in login_attempts:
        attempts, last_time = login_attempts[ip]
        if attempts >= 3 and now - last_time < 60:
            return jsonify({"error": "Too many attempts. Please wait 60 seconds."}), 429
        if now - last_time >= 60:
            login_attempts[ip] = [0, now]
    else:
        login_attempts[ip] = [0, now]

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # 3. Input length validation
    if not validate_input(username, MAX_USERNAME_LEN, "username") or \
       not validate_input(password, MAX_PASSWORD_LEN, "password"):
        return jsonify({"error": "Invalid input"}), 400

    # 1. Database connection context manager
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            
            if row and check_password_hash(row[0], password):
                login_attempts[ip] = [0, now]  # Reset on success
                return jsonify({"message": "Login successful"}), 200
            else:
                login_attempts[ip][0] += 1  # Track failures
                login_attempts[ip][1] = now
    except sqlite3.Error as e:
        logging.error(f"Database Error: {e}")
    
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/ping')
@secure_headers
@require_token
def ping():
    ip = request.args.get('ip', '')

    # 3. Input length validation
    if not validate_input(ip, MAX_IP_LEN, "ip"):
        return jsonify({"error": "Invalid IP"}), 400

    # 2. subprocess.run with timeout and check=True
    try:
        ip_obj = ipaddress.ip_address(ip)
        subprocess.run(
            ['ping', '-c', '1', str(ip_obj)],
            check=True,
            shell=False,
            timeout=5,
            capture_output=True,
            text=True
        )
        return jsonify({"message": f"Node {ip_obj} is reachable"}), 200
    except (ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logging.error(f"Network Audit Failure: {e}")
        return jsonify({"error": "Network check failed"}), 400

@app.route('/search')
@secure_headers
@require_token
def search():
    query = request.args.get('query', '')
    # 3. Input length validation
    if not validate_input(query, MAX_QUERY_LEN, "query"):
        return jsonify({"error": "Query too long"}), 400
    return render_template_string('<h1>Search results for: {{ query }}</h1>', query=query)

@app.route('/read')
@secure_headers
@require_token
def read_file():
    filename = request.args.get('file', '')
    # 3. Input length validation
    if not validate_input(filename, MAX_FILENAME_LEN, "file"):
        return jsonify({"error": "Invalid filename"}), 400

    safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))
    if not safe_path.startswith(BASE_DIR):
        logging.error(f"Path Traversal Attempt: {filename}")
        return jsonify({"error": "Access denied"}), 403

    try:
        with open(safe_path, 'r') as f:
            return f.read(), 200
    except FileNotFoundError:
        return jsonify({"error": "Resource not found"}), 404

# 5. Admin route with proper status codes
@app.route('/admin')
@secure_headers
@require_token
def admin():
    # Surgical admin check (always fails as per structural preservation)
    logging.warning(f"Unauthorized admin access attempt from {request.remote_addr}")
    return jsonify({"error": "Administrative access denied"}), 403

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=8000)