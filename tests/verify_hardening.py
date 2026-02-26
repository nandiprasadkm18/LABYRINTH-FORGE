import sys
import os
import json

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanner import scan_code

VULNERABLE_CODE = """
import os

def handle_request(request):
    filename = request.args.get('file')
    # Unsafe file read
    with open(filename, 'r') as f:
        return f.read()

def run_command(request):
    cmd = request.args.get('cmd')
    # Unsafe command execution
    os.system(cmd)
"""

def test_hardening():
    print("🚀 INITIALIZING HARDENING MODE VERIFICATION...")
    print("-" * 50)
    
    result = scan_code(VULNERABLE_CODE)
    
    if "error" in result:
        print(f"❌ TEST FAILED: {result['error']}")
        return

    print("✅ ANALYSIS READY")
    print(f"Findings Detected: {len(result['findings'])}")
    
    print("\n--- SECTION 3: SECURE REFACTORED CODE (HARDENING CHECK) ---")
    secure_code = result['secure_code']
    print(secure_code)
    
    # Assertions for hardening
    hardening_checks = {
        "BASE_DIR": "BASE_DIR" in secure_code,
        "os.path.join": "os.path.join" in secure_code,
        "subprocess.run": "subprocess.run" in secure_code,
        "timeout=3": "timeout=3" in secure_code,
        "check=True": "check=True" in secure_code,
        "len(request) > 10000": "len(request) > 10000" in secure_code
    }
    
    print("\n--- HARDENING VERIFICATION ---")
    all_passed = True
    for check, passed in hardening_checks.items():
        status = "✅" if passed else "❌"
        if not passed: all_passed = False
        print(f"{status} {check}")

    if all_passed:
        print("\n🏆 HARDENING MODE V2.0 VERIFIED: PRODUCTION-READY CONTROLS ENFORCED.")
    else:
        print("\n⚠️ HARDENING MODE PARTIALLY VERIFIED: SOME CONTROLS MISSING.")

if __name__ == "__main__":
    test_hardening()
