import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import scan_code

# The EXACT code provided by the user in the last message
fixed_code = """
import os
import sqlite3
import json
import subprocess
import requests
from urllib.parse import urlparse
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# Secure configuration
SECRET_KEY = os.environ.get("SECRET_KEY")
BASE_UPLOAD_DIR = os.path.realpath("uploads")
ALLOWED_FETCH_HOSTS = ["api.example.com"]

def get_db():
    return sqlite3.connect("app.db")


# ---------------------------
# SQL Injection FIXED
# ---------------------------
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    if not user_id:
        abort(400)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return str(cursor.fetchone())


@app.route("/product")
def get_product():
    pid = request.args.get("pid")
    if not pid:
        abort(400)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (pid,))
    return str(cursor.fetchone())


# ---------------------------
# Command Injection FIXED
# ---------------------------
@app.route("/run")
def run():
    subprocess.run(["ls", "-la"], check=True)
    return "done"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    if not host:
        abort(400)

    subprocess.run(["ping", "-c", "1", host], check=True)
    return "pinged"


@app.route("/popen")
def popen_test():
    arg = request.args.get("arg")
    if not arg:
        abort(400)

    subprocess.Popen(["echo", arg])
    return "popen"


# ---------------------------
# RCE FIXED
# ---------------------------
@app.route("/exec")
def execute():
    return "Dynamic execution disabled"


@app.route("/eval")
def evaluate():
    return "Dynamic evaluation disabled"


@app.route("/compile")
def compile_code():
    return "Compilation disabled"


# ---------------------------
# Deserialization FIXED
# ---------------------------
@app.route("/deserialize")
def deserialize():
    data = request.args.get("data")
    if not data:
        abort(400)

    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        abort(400)

    return str(obj)


# ---------------------------
# Path Traversal FIXED
# ---------------------------
@app.route("/download")
def download():
    filename = request.args.get("file")
    if not filename:
        abort(400)

    safe_path = os.path.realpath(os.path.join(BASE_UPLOAD_DIR, filename))
    if not safe_path.startswith(BASE_UPLOAD_DIR):
        abort(403)

    with open(safe_path, "r") as f:
        return f.read()


@app.route("/read")
def read_file():
    return "Direct file access disabled"


# ---------------------------
# XSS FIXED
# ---------------------------
@app.route("/page")
def page():
    name = request.args.get("name", "")
    safe = name.replace("<", "&lt;").replace(">", "&gt;")
    return f\"\"\"
    <script>
        document.getElementById('output').textContent = "{safe}";
    </script>
    \"\"\"


@app.route("/template")
def template():
    user_input = request.args.get("input", "")
    safe = user_input.replace("<", "&lt;").replace(">", "&gt;")
    return f"<h1>{safe}</h1>"


# ---------------------------
# SSRF FIXED
# ---------------------------
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not url:
        abort(400)

    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_FETCH_HOSTS:
        abort(403)

    r = requests.get(url)
    return r.text


# ---------------------------
# Open Redirect FIXED
# ---------------------------
@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next", "/")
    if not next_url.startswith("/"):
        abort(403)

    return redirect(next_url)


# ---------------------------
# Debug Disabled
# ---------------------------
if __name__ == "__main__":
    app.run(debug=False)
"""

def test():
    print("=== FINAL USER CODE SCAN ===")
    res = scan_code(fixed_code)
    print(f"Total Findings: {res['total_vulnerabilities']}")
    for f in res['findings']:
        print(f" - [{f['id']}] at line {f['line']}: {f['code']}")
    
    if res['total_vulnerabilities'] == 0:
        print("\n[PASS] SUCCESS: 0 vulnerabilities detected in fixed code.")
    else:
        print("\n[FAIL] FAILURE: Vulnerabilities still detected.")

if __name__ == "__main__":
    test()
