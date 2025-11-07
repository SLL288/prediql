import requests
import logging
import time
import random
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

    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            logger.info(f"Attempting Llama request (attempt {attempt + 1}/{max_retries + 1})")
            
            response = requests.post(
                url,
                headers={"Content-Type": "application/json"},
                json=data,
                timeout=6000
            )
            response.raise_for_status()
            logger.info("Get response from Llama successfully.")
            return response.json()["message"]["content"]
            
        except requests.exceptions.Timeout as e:
            last_exception = e
            logger.warning(f"Request timeout on attempt {attempt + 1}: {e}")
            
        except requests.exceptions.ConnectionError as e:
            last_exception = e
            logger.warning(f"Connection error on attempt {attempt + 1}: {e}")
            
        except requests.exceptions.RequestException as e:
            last_exception = e
            logger.warning(f"Request failed on attempt {attempt + 1}: {e}")
            
        except Exception as e:
            last_exception = e
            logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
            break
        
        # If we haven't returned or broken, we need to retry
        if attempt < max_retries:
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            logger.info(f"Retrying in {delay:.2f} seconds...")
            time.sleep(delay)
        else:
            logger.error(f"All {max_retries + 1} attempts failed. Last error: {last_exception}")
            raise Exception(f"Failed to get response from Llama after {max_retries + 1} attempts. Last error: {last_exception}")


def safe_api_call(api_function, prompt, fallback_function=None, **kwargs):
    """
    Safely call an API function with fallback options.
    
    Args:
        api_function: The primary API function to call
        prompt (str): The prompt to send
        fallback_function: Optional fallback function if primary fails
        **kwargs: Additional arguments for the API function
    
    Returns:
        str: The API response content
        
    Raises:
        Exception: If all attempts fail
    """
    try:
        logger.info(f"Attempting primary API call: {api_function.__name__}")
        return api_function(prompt, **kwargs)
    except Exception as e:
        logger.error(f"Primary API call failed: {e}")
        
        if fallback_function:
            logger.info(f"Attempting fallback API call: {fallback_function.__name__}")
            try:
                return fallback_function(prompt, **kwargs)
            except Exception as fallback_e:
                logger.error(f"Fallback API call also failed: {fallback_e}")
                raise Exception(f"Both primary and fallback API calls failed. Primary: {e}, Fallback: {fallback_e}")
        else:
            raise e
