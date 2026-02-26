import sys
import os
import json

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.scanner import scan_code

ADVERSARIAL_CODE = """
import sqlite3
import os
import pickle
import eval

def vulnerable_app(user_input):
    # 1. SQL Injection
    db = sqlite3.connect("users.db")
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM accounts WHERE id = '{user_input}'")
    
    # 2. Command Injection
    os.system("ls -la " + user_input)
    
    # 3. Code Injection
    eval(user_input)
    
    # 4. Insecure Deserialization
    data = pickle.loads(user_input)
    
    # 5. Hardcoded Secret
    AWS_SECRET = "AKIA_FAKE_SECRET_KEY_12345"
    
    return "Operations completed."
"""

def test_engine():
    print("🚀 INITIALIZING AUTONOMOUS REMEDIATION TEST...")
    print("-" * 50)
    
    result = scan_code(ADVERSARIAL_CODE)
    
    if "error" in result:
        print(f"❌ TEST FAILED: {result['error']}")
        return

    print("✅ ANALYSIS READY")
    print(f"Findings Detected: {len(result['findings'])}")
    
    print("\n--- SECTION 1: FINDINGS (PREVIEW) ---")
    for f in result['findings']:
        print(f"[{f['id']}] {f['type']} (Severity: {f['severity']}) at Line {f['line']}")

    print("\n--- SECTION 4: SECURITY SCORE (FROM REPORT) ---")
    # Extract score from report text if possible or just print report
    print(result['report'])

if __name__ == "__main__":
    test_engine()
