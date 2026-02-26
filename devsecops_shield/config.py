import os
from dotenv import load_dotenv

# Load environment from root or backend if needed
# For hackathon portability, we check both
load_dotenv() # Check current dir
backend_env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend', '.env')
load_dotenv(backend_env)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not GROQ_API_KEY:
    # Fail-fast as per requirements
    raise RuntimeError("GROQ_API_KEY not set in environment.")

MODEL = "llama-3.3-70b-versatile"
