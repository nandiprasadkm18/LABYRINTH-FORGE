import sys
import os
import ast

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from scanner import scan_code
except Exception as e:
    print(f"CRITICAL: Failed to import scanner: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# The "Ultimate Stress Test" code including the user's broken scenarios
stress_test_code = """
import os
import sqlite3
import requests
import pickle
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)
SECRET_KEY = "hardcoded-secret-key"

@app.route("/broken")
def broken_logic():
    pid = request.args.get("pid")
    # SQLi 1
    db.execute("SELECT * FROM users WHERE id = " + pid)
    # SQLi 2 (format)
    query = "SELECT * FROM products WHERE id = '{}'".format(pid)
    db.execute(query)
    
    # Path Traversal
    filename = request.args.get("file")
    with open(os.path.join("uploads", filename), "r") as f:
        data = f.read()
    
    # SSTI
    user_input = request.args.get("q")
    return render_template_string("<h1>" + user_input + "</h1>")

@app.route("/redirect")
def redir():
    url = request.args.get("url")
    return redirect(url)

if __name__ == "__main__":
    app.run(debug=True)
"""

def test():
    print("=== AST MATURITY 10/10 VERIFICATION ===")
    
    import scanner
    original_client = scanner.client
    scanner.client = None
    scanner.OLLAMA_URL = "http://disabled" # Force fallback
    
    print("[PHASE 1] Scanning code...")
    try:
        res = scan_code(stress_test_code)
        patched = res["final_code"]
        print("[PHASE 1] Scanning complete.")
    except Exception as e:
        print(f"[FAIL] Scan crashed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print("\n[METRICS]")
    print(f"Source: {res['patch_metrics']['source']}")
    print(f"Honest Confidence: {res['patch_metrics']['confidence']}%")
    print(f"Syntax Valid: {res['patch_metrics']['syntax_valid']}")

    # DEBUG: Print patched code
    print("\n--- PATCHED CODE START ---")
    print(patched)
    print("--- PATCHED CODE END ---\n")

    # 1. No Syntax Errors
    print("[PHASE 2] Checking Syntax...")
    try:
        ast.parse(patched)
        print("[PASS] No Syntax Errors.")
    except SyntaxError as e:
        print(f"[FAIL] Syntax Error: {e.msg} at line {e.lineno}")
        import traceback
        traceback.print_exc()
    print("[PHASE 2] Syntax check complete.")

    # 2. Helper Injection
    print("[PHASE 3] Checking Helpers...")
    if "_safe_redirect" in patched and "_safe_open" in patched:
        print("[PASS] Secure helpers injected.")
    else:
        print("[FAIL] Secure helpers missing.")

    # 3. Debug Mode
    print("[PHASE 4] Checking Debug Mode...")
    if "debug=True" not in patched and "debug=False" in patched:
        print("[PASS] Debug mode disabled.")
    else:
        print("[FAIL] Debug mode still enabled.")

    # 4. Hardcoded Secret
    print("[PHASE 5] Checking Secrets...")
    if "SECRET_KEY = _os.environ.get" in patched:
         print("[PASS] Hardcoded secret removed.")
    else:
         print("[FAIL] Hardcoded secret still present.")

    # 5. SQLi
    print("[PHASE 6] Checking SQLi...")
    if "/* FIXED: Parameterized query */" in patched:
         print("[PASS] SQLi fixed.")
    else:
         print("[FAIL] SQLi remains.")

    scanner.client = original_client
    print("\n=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    test()
