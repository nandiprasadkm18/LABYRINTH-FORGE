import os
import sys
from dotenv import load_dotenv

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

load_dotenv("backend/.env")

from scanner import scan_code

def test_scan():
    # This code has a regex-detectable CMDI (os.system) 
    # and a logic flaw/complex vulnerability (a mock insecure state update)
    code = """
import os
import json

def process_data(user_input):
    # Regex should catch this
    os.system("echo " + user_input)
    
    # AI should catch this potential logic floor / insecure state
    data = json.loads(user_input)
    if data.get("admin") == "true":
        # AI might see this as a vulnerability if user_input is untrusted
        enable_root_access()

def enable_root_access():
    pass
    """
    print("Testing hybrid scanner (Regex + AI)...")
    result = scan_code(code)
    
    print(f"\nTotal Vulnerabilities found: {result['total_vulnerabilities']}")
    for f in result['findings']:
        print(f"- [{f.get('id', 'AI-FINDING')}] {f['name']} (Severity: {f['severity']}) at line {f['line']}")
        print(f"  Desc: {f['description']}")
    
    if result['ai_patch']:
        print("\nAI Patch generated!")
        print(f"Confidence: {result['patch_metrics']['confidence']}%")
    else:
        print("\nFAILED: No AI patch generated.")

if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY NOT FOUND IN .env")
    else:
        test_scan()
