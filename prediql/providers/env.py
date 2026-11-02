"""Minimal .env loader and API-key resolution (stdlib only).

Keys resolve **per vendor, with a shared fallback**:

1. ``<VENDOR>_API_KEY`` — e.g. ``ANTHROPIC_API_KEY``, ``OPENROUTER_API_KEY``,
   ``ZAI_API_KEY``;
2. ``LLM_API_KEY`` — the general fallback for any vendor without its own.

One key is enough when you use one vendor, which keeps the simple case simple.
A cross-vendor sweep needs a key per vendor, because Anthropic will not accept an
OpenRouter token — with a single shared key, every model outside that one vendor
fails to authenticate. Kept dependency-free rather than pulling in python-dotenv
for a dozen lines.
"""

from __future__ import annotations

import os
from pathlib import Path

#: The shared fallback key, used for any vendor without a dedicated one.
API_KEY_VAR = "LLM_API_KEY"


def vendor_key_var(vendor: str) -> str:
    """Environment variable name for a vendor's dedicated key."""
    return f"{vendor.strip().upper()}_API_KEY"


#: The repo root, derived from this file's location (prediql/providers/env.py).
#: The ``.env`` is anchored here rather than to the process cwd, because callers
#: legitimately run from elsewhere — the dashboard backend runs from
#: ``dashboard/backend/``, and a cwd-relative lookup silently found no keys there.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def dotenv_path() -> Path:
    """Where the ``.env`` is read from: the repo root, else the cwd."""
    anchored = _REPO_ROOT / ".env"
    return anchored if anchored.exists() else Path(".env")


def load_dotenv(path: Path | str | None = None) -> dict[str, str]:
    """Parse ``KEY=value`` lines into a dict, ignoring comments and blanks.

    Does not overwrite variables already in the environment, so an explicit
    ``export`` wins over the file — the usual dotenv precedence.
    """
    path = Path(path) if path is not None else dotenv_path()
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        values[key] = value
        os.environ.setdefault(key, value)
    return values


def api_key(explicit: str | None = None, vendor: str | None = None) -> str | None:
    """Resolve an API key: explicit value, then the vendor's key, then the fallback.

    ``vendor`` is the provider name (``anthropic``/``openrouter``/``zai``/…).
    Passing ``None`` resolves only the shared key, which is what a single-vendor
    caller wants.
    """
    if explicit:
        return explicit
    load_dotenv()
    if vendor:
        specific = os.environ.get(vendor_key_var(vendor))
        if specific:
            return specific
    return os.environ.get(API_KEY_VAR)


def key_requirements(vendor: str) -> dict[str, str]:
    """The env variables a vendor needs, and whether each is set.

    Used by the dashboard to tell an operator exactly what to add to ``.env``
    for a custom model, without ever transporting the secret itself.
    """
    load_dotenv()
    known = {"anthropic", "openrouter", "zai", "ollama", "echo"}
    needs = {vendor_key_var(vendor): bool(os.environ.get(vendor_key_var(vendor)))
             or bool(os.environ.get(API_KEY_VAR))}
    if vendor not in known:
        base = f"{vendor.upper()}_BASE_URL"
        needs[base] = bool(os.environ.get(base))
    return needs


def configured_vendors(vendors: tuple[str, ...]) -> dict[str, str]:
    """Which of ``vendors`` have a usable key, and where it came from.

    Lets the dashboard warn *before* a nine-run cross-vendor sweep fails on
    authentication halfway through.
    """
    load_dotenv()
    shared = bool(os.environ.get(API_KEY_VAR))
    result: dict[str, str] = {}
    for vendor in vendors:
        if os.environ.get(vendor_key_var(vendor)):
            result[vendor] = vendor_key_var(vendor)
        elif shared:
            result[vendor] = API_KEY_VAR
        else:
            result[vendor] = ""
    return result
