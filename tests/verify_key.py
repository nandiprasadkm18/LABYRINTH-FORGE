import os
import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path="backend/.env", override=True)

def test_key():
    key = os.getenv("GROQ_API_KEY")
    print(f"Testing key: {key[:10]}...")
    
    url = "https://api.groq.com/openai/v1/models"
    headers = {"Authorization": f"Bearer {key}"}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print("✅ API Key is VALID!")
        else:
            print(f"❌ API Key is INVALID! Status: {response.status_code}")
            print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_key()
