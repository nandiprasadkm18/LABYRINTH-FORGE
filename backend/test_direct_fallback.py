import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import _fallback_patch

# Test Case: Direct fallback test
code_vuln = """
def my_api():
    url = request.args.get("url")
    data = requests.get(url).text
    return data

@app.route("/path")
def path_traversal():
    f = open("uploads/" + filename)
    return f.read()
"""

def test():
    print("=== DIRECT FALLBACK TEST ===")
    
    patch = _fallback_patch(code_vuln, [])
    
    print("\n[PATCH OUTPUT START]")
    print(patch)
    print("[PATCH OUTPUT END]\n")
    
    # 1. Check Header
    if "Secure Configuration" in patch and "ALLOWED_FETCH_HOSTS" in patch:
        print("[PASS] SUCCESS: Header found.")
    else:
        print("[FAIL] FAILURE: Header missing.")

    # 2. Check SSRF
    if "urlparse(url)" in patch and "ALLOWED_FETCH_HOSTS" in patch:
        print("[PASS] SUCCESS: SSRF fixed.")
    else:
        print("[FAIL] FAILURE: SSRF not fixed.")

    # 3. Check Structure Preservation
    if "@app.route(\"/path\")" in patch and "def path_traversal():" in patch:
        print("[PASS] SUCCESS: Structure preserved.")
    else:
        print("[FAIL] FAILURE: Structure destroyed.")
    
    # Check Path Traversal Fix
    if "BASE_UPLOAD_DIR" in patch and "startswith(BASE_UPLOAD_DIR)" in patch:
        print("[PASS] SUCCESS: Path Traversal fixed with BASE_UPLOAD_DIR.")
    else:
        print("[FAIL] FAILURE: Path Traversal fix incorrect.")

if __name__ == "__main__":
    test()
