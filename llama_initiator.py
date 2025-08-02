import requests
import logging
from google import genai


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_gemini_model(prompt):
    print("Using Gemini model")
    client = genai.Client()
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=[prompt]
    )
    return response.text

def get_llm_model(prompt):
    url = "http://localhost:11434/api/chat"
    data = {
        "model": "llama3",
        "messages": [
            {
                "role": "user",
                "content": prompt

            }
        ],
        "stream": False,
        "temperature": 1.2,
        "top_k": 50,
        "top_p": 0.95,
    }

    try:
        response = requests.post(
            url,
            headers={"Content-Type": "application/json"},
            json=data,
            timeout=6000
        )
        response.raise_for_status()
        logger.info("Get response from LLama successfully.")
        return response.json()["message"]["content"]
    except requests.exceptions.RequestException as e:
        raise Exception("Get response from LLama failed.")
