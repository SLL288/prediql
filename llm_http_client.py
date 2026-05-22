import logging
import random
import time
from dataclasses import dataclass

import requests

from config import Config
from llm_cost_tracker import record_llm_usage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

max_retries = 3
base_delay = 1.0
headers = {"Content-Type": "application/json"}


@dataclass
class LLMChatResult:
    """One chat completion from the configured LLM endpoint (Ollama-compatible)."""

    text: str
    prompt_tokens: int
    completion_tokens: int
    wall_time_seconds: float


def _estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(len(text) / 4))


def _resolve_chat_url_model(provider: str) -> tuple[str, str]:
    """Resolve chat URL and model name (always primary ``Config`` endpoint)."""
    _ = provider  # reserved for future multi-endpoint; Jaccard is offline-only.
    url = (getattr(Config, "PRIMARY_LLM_API_URL", None) or "").strip()
    if not url:
        url = "http://localhost:11434/api/chat"
    model = (getattr(Config, "PRIMARY_LLM_MODEL", None) or "llama3").strip()
    return url, model


def get_llm_model(
    prompt: str, node_label: str = "", provider: str = "primary"
) -> LLMChatResult:
    """
    POST to Ollama-compatible ``/api/chat`` (primary URL/model from ``Config``).

    Parses ``prompt_eval_count`` / ``eval_count`` when present; otherwise uses
    rough character/4 estimates. Records usage on ``llm_cost_tracker``.
    """
    last_exception = None

    for attempt in range(max_retries + 1):
        url, model = _resolve_chat_url_model(provider)
        temp = float(getattr(Config, "LLM_TEMPERATURE", 0.0))
        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "temperature": temp,
            "top_k": 50,
            "top_p": 0.95,
        }
        usage_label = f"{node_label}|{provider}" if node_label else str(provider)
        t0 = time.perf_counter()
        try:
            logger.info(
                "Attempting LLM API request (attempt %s/%s)",
                attempt + 1,
                max_retries + 1,
            )

            req_headers = dict(headers)

            llm_key = getattr(Config, "LLM_API_KEY", None)
            if llm_key:
                ks = str(llm_key).strip()
                low = ks.lower()
                if low.startswith("bearer ") or low.startswith("basic "):
                    req_headers["Authorization"] = ks
                else:
                    req_headers["Authorization"] = f"Bearer {ks}"

            response = requests.post(
                url,
                headers=req_headers,
                json=data,
                timeout=6000,
            )

            if response.status_code != 200:
                response_data = response.json() if response.content else {}
                logger.warning("HTTP %s: %s", response.status_code, response_data)
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    logger.error("Client error %s, not retrying", response.status_code)
                    raise Exception(f"Client error: {response.status_code}")
                if response.status_code >= 500 or response.status_code == 429:
                    raise requests.exceptions.RequestException(
                        f"HTTP {response.status_code}"
                    )

            response.raise_for_status()
            logger.info("Get response from LLM API successfully.")

            response_data = response.json()
            wall = time.perf_counter() - t0

            # OpenAI-style (legacy / other gateways)
            if "choices" in response_data and len(response_data["choices"]) > 0:
                msg = response_data["choices"][0].get("message") or {}
                content = msg.get("content") or ""
                usage = response_data.get("usage") or {}
                pt = int(usage.get("prompt_tokens") or usage.get("input_tokens") or 0)
                ct = int(
                    usage.get("completion_tokens")
                    or usage.get("output_tokens")
                    or 0
                )
                if not pt:
                    pt = _estimate_tokens(prompt)
                if not ct:
                    ct = _estimate_tokens(content)
                record_llm_usage(pt, ct, wall, usage_label)
                return LLMChatResult(content, pt, ct, wall)

            # Ollama /api/chat
            if "message" in response_data and response_data["message"]:
                msg = response_data["message"]
                content = msg.get("content") or ""
                pt = int(response_data.get("prompt_eval_count") or 0)
                ct = int(response_data.get("eval_count") or 0)
                if not pt:
                    pt = _estimate_tokens(prompt)
                if not ct:
                    ct = _estimate_tokens(content)
                record_llm_usage(pt, ct, wall, usage_label)
                return LLMChatResult(content, pt, ct, wall)

            raise Exception("Invalid response format from LLM API")

        except requests.exceptions.Timeout as e:
            last_exception = e
            logger.warning("Request timeout on attempt %s: %s", attempt + 1, e)

        except requests.exceptions.ConnectionError as e:
            last_exception = e
            logger.warning("Connection error on attempt %s: %s", attempt + 1, e)

        except requests.exceptions.RequestException as e:
            last_exception = e
            logger.warning("Request failed on attempt %s: %s", attempt + 1, e)

        except KeyError as e:
            last_exception = e
            logger.error("Response parsing failed on attempt %s: %s", attempt + 1, e)
            break

        except Exception as e:
            last_exception = e
            logger.error("Unexpected error on attempt %s: %s", attempt + 1, e)
            break

        if attempt < max_retries:
            delay = base_delay * (2**attempt) + random.uniform(0, 1)
            logger.info("Retrying in %.2f seconds...", delay)
            time.sleep(delay)
        else:
            logger.error(
                "All %s attempts failed. Last error: %s", max_retries + 1, last_exception
            )
            raise Exception(
                f"Failed to get response from LLM API after {max_retries + 1} attempts. Last error: {last_exception}"
            )

    raise Exception(f"Failed to get response from LLM API. Last error: {last_exception}")
