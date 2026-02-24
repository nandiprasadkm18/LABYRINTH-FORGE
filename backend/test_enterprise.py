import sys
import os

# Add the current directory to sys.path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner import scan_code

# Test Case 1: False Positive Avoidance
code_fp = """
import subprocess
# FIXED: shell=True removed
subprocess.run(["ls"], shell=False)

def safe_redirect(url):
    if url.startswith("/"):
        return redirect(url) # Validated - Should NOT be flagged
    return redirect("/")      # literal - Should NOT be flagged
"""

# Test Case 2: Structural Fallback
code_struct = """
@app.route("/redirect")
def my_redirect():
    url = request.args.get('url')
    return redirect(url) # Unvalidated - Should be fixed
"""

# Test Case 3: Cannonical Metrics
code_metrics = """
import os
os.system("ls " + folder) # CMDI
"""

def test():
    print("=== ENTERPRISE SCANNER TEST ===")
    
    # 1. FP Check
    res1 = scan_code(code_fp)
    v_ids = [f["id"] for f in res1["findings"]]
    print(f"FP Scan Total: {res1['total_vulnerabilities']} IDs: {v_ids}")
    if res1['total_vulnerabilities'] == 0:
        print("✅ SUCCESS: No false positives found in comments/validated redirects.")
    else:
        print("❌ FAILURE: False positives detected.")

    # 2. Structural Check
    print("\n2. Structural Fallback Check:")
    res2 = scan_code(code_struct)
    patch = res2["ai_patch"]
    if "def my_redirect()" in patch and "@app.route" in patch:
        print("✅ SUCCESS: Function and decorator preserved.")
    else:
        print("❌ FAILURE: Structure destroyed.")
        print(patch)

    # 3. Metrics Check
    print("\n3. Metrics Accuracy Check:")
    res3 = scan_code(code_metrics)
    m = res3["patch_metrics"]
    print(f"Before: {m['before']}, After: {m['after']}, Reduction: {m['reduction']}")
    if m['before'] > 0 and m['after'] == 0:
        print("✅ SUCCESS: Metrics correctly identified fix.")
    else:
        print("❌ FAILURE: Metrics mismatch.")

    print("\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    test()
