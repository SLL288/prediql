import requests
import logging
import time
import random


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
    
    for attempt in range(max_retries + 1):  # +1 for initial attempt
        try:
            logger.info(f"Attempting LLM API request (attempt {attempt + 1}/{max_retries + 1})")
            
            response = requests.post(
                url,
                headers=headers,
                json=data,
                timeout=6000
            )
            
            # Check for HTTP errors
            if response.status_code != 200:
                response_data = response.json() if response.content else {}
                logger.warning(f"HTTP {response.status_code}: {response_data}")
                
                # Don't retry on client errors (4xx) except rate limiting
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    logger.error(f"Client error {response.status_code}, not retrying")
                    raise Exception(f"Client error: {response.status_code}")
                
                # Retry on server errors (5xx) and rate limiting (429)
                if response.status_code >= 500 or response.status_code == 429:
                    raise requests.exceptions.RequestException(f"HTTP {response.status_code}")
            
            response.raise_for_status()
            logger.info("Get response from LLM API successfully.")
            
            # Parse the response according to LLM API format
            response_data = response.json()
            if "choices" in response_data and len(response_data["choices"]) > 0:
                return response_data["choices"][0]["message"]["content"]
            else:
                raise Exception("Invalid response format from LLM API")
                
        except requests.exceptions.Timeout as e:
            last_exception = e
            logger.warning(f"Request timeout on attempt {attempt + 1}: {e}")
            
        except requests.exceptions.ConnectionError as e:
            last_exception = e
            logger.warning(f"Connection error on attempt {attempt + 1}: {e}")
            
        except requests.exceptions.RequestException as e:
            last_exception = e
            logger.warning(f"Request failed on attempt {attempt + 1}: {e}")
            
        except KeyError as e:
            last_exception = e
            logger.error(f"Response parsing failed on attempt {attempt + 1}: {e}")
            # Don't retry parsing errors as they're likely permanent
            break
            
        except Exception as e:
            last_exception = e
            logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
            # Don't retry unexpected errors as they might be permanent
            break
        
        # If we haven't returned or broken, we need to retry
        if attempt < max_retries:
            # Calculate delay with exponential backoff and jitter
            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
            logger.info(f"Retrying in {delay:.2f} seconds...")
            time.sleep(delay)
        else:
            logger.error(f"All {max_retries + 1} attempts failed. Last error: {last_exception}")
            raise Exception(f"Failed to get response from LLM API after {max_retries + 1} attempts. Last error: {last_exception}")
