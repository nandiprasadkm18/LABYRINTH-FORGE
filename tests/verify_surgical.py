import requests
import base64
import os

URL = "http://127.0.0.1:8000"
TOKEN = os.environ.get("SHIELD_API_TOKEN", "default_token_if_set")

def test_size_limit():
    print("Testing 4KB limit...")
    large_data = "A" * 5000
    try:
        r = requests.post(f"{URL}/login", data={"username": "admin", "password": large_data})
        print(f"Status: {r.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def test_b64_validation():
    print("Testing B64 structural validation...")
    # Invalid B64 (contains $)
    invalid_b64 = "YWRtaW4k"
    r = requests.post(f"{URL}/b64", data={"data": invalid_b64})
    print(f"Invalid Output Status: {r.status_code}")
    
    valid_b64 = base64.b64encode(b"admin").decode()
    r = requests.post(f"{URL}/b64", data={"data": valid_b64})
    print(f"Valid Output Status: {r.status_code}")

if __name__ == "__main__":
    # This assumes the app is running
    print("Verification Script Initialized.")
    # test_size_limit()
    # test_b64_validation()
