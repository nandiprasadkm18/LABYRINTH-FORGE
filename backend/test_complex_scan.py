import os
import sys
import json
from dotenv import load_dotenv

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))
load_dotenv("backend/.env")

from scanner import scan_code

def run_complex_scan():
    code = """
import os
import sqlite3
import pickle
import subprocess
from flask import Flask, request, redirect

app = Flask(__name__)

# ─────────────────────────────────────
# Hardcoded Secrets
# ─────────────────────────────────────
API_KEY = "sk-test-123456789"
password = "SuperSecretPassword"

# ─────────────────────────────────────
# SQL Injection (f-string)
# ─────────────────────────────────────
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return str(cursor.fetchone())

# ─────────────────────────────────────
# SQL Injection (string concat)
# ─────────────────────────────────────
@app.route("/search")
def search():
    term = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username LIKE '%" + term + "%'")
    return str(cursor.fetchall())

# ─────────────────────────────────────
# Command Injection (os.system)
# ─────────────────────────────────────
@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    os.system("ls -la " + cmd)
    return "done"

# ─────────────────────────────────────
# Command Injection (shell=True)
# ─────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run("ping -c 1 " + host, shell=True)
    return "pinged"

# ─────────────────────────────────────
# Remote Code Execution (exec / eval)
# ─────────────────────────────────────
@app.route("/exec")
def execute():
    code = request.args.get("code")
    exec(code)
    return "executed"

@app.route("/eval")
def evaluate():
    expression = request.args.get("expr")
    return str(eval(expression))

# Dangerous compile usage
@app.route("/compile")
def compile_code():
    code = request.args.get("code")
    compiled = compile(code, "<string>", "exec")
    return str(compiled)

# ─────────────────────────────────────
# Insecure Deserialization
# ─────────────────────────────────────
@app.route("/deserialize")
def deserialize():
    data = request.args.get("data")
    obj = pickle.loads(bytes.fromhex(data))
    return str(obj)

# ─────────────────────────────────────
# Path Traversal
# ─────────────────────────────────────
@app.route("/download")
def download():
    filename = request.args.get("file")
    with open("uploads/" + filename, "r") as f:
        return f.read()

# ─────────────────────────────────────
# XSS (innerHTML)
# ─────────────────────────────────────
@app.route("/page")
def render_page():
    name = request.args.get("name")
    return f\"\"\"
    <script>
        document.getElementById('output').innerHTML = '{name}'
    </script>
    \"\"\"

# XSS (document.write)
@app.route("/write")
def write_page():
    data = request.args.get("data")
    return f\"\"\"
    <script>
        document.write("{data}")
    </script>
    \"\"\"

# ─────────────────────────────────────
# Open Redirect
# ─────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    url = request.args.get("next")
    return redirect(url)

# ─────────────────────────────────────
# Debug Mode Enabled
# ─────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
"""
    print("Running deep scan and patch...")
    result = scan_code(code)
    
    print(f"\nVulnerabilities Before: {result['total_vulnerabilities']}")
    print(f"Vulnerabilities After: {result['patch_metrics']['after']}")
    print(f"Reduction: {result['patch_metrics']['reduction']}")
    print(f"Confidence: {result['patch_metrics']['confidence']}%")
    
    if result['patch_metrics']['after'] > 0:
        print("\nSome vulnerabilities remained. Investigating...")
        # Print AI patch to see what it did
        # print(result['ai_patch'])

if __name__ == "__main__":
    run_complex_scan()
