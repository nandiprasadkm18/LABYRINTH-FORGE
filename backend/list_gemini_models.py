import os
from google import genai
from dotenv import load_dotenv

load_dotenv("backend/.env")

def list_models():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("GEMINI_API_KEY not found")
        return

    client = genai.Client(api_key=api_key)
    print("Available Gemini Models:")
    try:
        models = list(client.models.list())
        with open("backend/models_list.txt", "w") as f:
            for m in models:
                f.write(f"MODEL: {m.name}\n")
        print("Model list saved to backend/models_list.txt")
    except Exception as e:
        print(f"Error listing models: {e}")

if __name__ == "__main__":
    list_models()
