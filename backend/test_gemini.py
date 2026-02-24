import os
import sys
from dotenv import load_dotenv

# Add backend to path
sys.path.append(os.path.join(os.getcwd(), "backend"))

load_dotenv("backend/.env")

from scanner import scan_code

def test_scan():
    code = """
import os
import json

def process_data(user_input):
    # Regex + AI should catch this
    os.system("echo " + user_input)
    
    # AI should catch this potential logic flaw
    data = json.loads(user_input)
    if data.get("admin") == "true":
        enable_root_access()

def enable_root_access():
    pass
    """
    print("Testing scanner with Gemini Integration...")
    result = scan_code(code)
    
    print(f"\nTotal Vulnerabilities found: {result['total_vulnerabilities']}")
    for f in result['findings']:
        print(f"- [{f.get('id', 'AI-FINDING')}] {f['name']} (Severity: {f['severity']}) at line {f['line']}")
        print(f"  Desc: {f['description']}")
    
    if result['ai_patch']:
        print("\nGemini (New SDK) Patch generated!")
        print(f"Confidence: {result['patch_metrics']['confidence']}%")
        print("\nPatch Preview:")
        print("-" * 20)
        # Handle cases where report format is different
        print(result['ai_patch'][:500] + "...")
        print("-" * 20)
    else:
        print("\nFAILED: No patch generated.")

if __name__ == "__main__":
    if not os.environ.get("GEMINI_API_KEY"):
        print("ERROR: GEMINI_API_KEY NOT FOUND IN .env")
    else:
        test_scan()
