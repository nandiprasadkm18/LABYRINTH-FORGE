import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import scan_code

# Test Case: Complex vulnerable app with structure and new rule types
code_complex = """
from flask import Flask, request, render_template_string
import requests
import pickle

app = Flask(__name__)

@app.route("/ssrf")
def ssrf_fix():
    url = request.args.get("url")
    r = requests.get(url)
    return r.text

@app.route("/template")
def template_fix():
    user_input = request.args.get("q")
    return render_template_string("<h1>" + user_input + "</h1>")

@app.route("/pickle")
def pickle_fix():
    data = request.args.get("data")
    obj = pickle.loads(data)
    return str(obj)

if __name__ == "__main__":
    app.run(debug=True)
"""

def test():
    print("=== EXPERT SCANNER TEST ===")
    
    # 1. Run scan (forcing fallback by temporarily disabling client if needed, 
    # but here we just want to see the fallback output structure)
    # Actually, scan_code will try AI first. 
    # I'll mock client to None to force fallback.
    import scanner
    original_client = scanner.client
    scanner.client = None
    
    res = scan_code(code_complex)
    patch = res["ai_patch"]
    
    print("\nPatch Source:", res["patch_metrics"]["source"])
    
    # Check SSRF Fix
    if "ALLOWED_FETCH_HOSTS" in patch and "parsed.hostname" in patch:
        print("✅ SUCCESS: SSRF rule applied.")
    else:
        print("❌ FAILURE: SSRF rule missing.")

    # Check Template Fix
    if "replace('<','&lt;')" in patch:
        print("✅ SUCCESS: Template escaping applied.")
    else:
        print("❌ FAILURE: Template escaping missing.")

    # Check Structure
    if "@app.route(\"/ssrf\")" in patch and "def ssrf_fix():" in patch:
        print("✅ SUCCESS: Structure preserved for SSRF.")
    else:
        print("❌ FAILURE: Structure destroyed for SSRF.")

    # Check Metrics
    print(f"Reduction: {res['patch_metrics']['reduction']}/{res['patch_metrics']['before']}")
    
    # Restore client
    scanner.client = original_client

    print("\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    test()
