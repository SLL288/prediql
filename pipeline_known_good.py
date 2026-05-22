"""Persist and load the Stage-1 known-good GraphQL query for Stage 2 / Stage 3."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

import requests

from config import Config, run_node_dir
from graphql_send_payload import graphql_request_headers, is_successful_graphql_response


def known_good_path(node: str) -> str:
    return os.path.join(run_node_dir(node), "known_good.json")


def save_known_good(node: str, query_text: str, meta: Optional[Dict[str, Any]] = None) -> None:
    path = known_good_path(node)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    doc = {
        "query": query_text.strip(),
        "meta": meta or {},
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    print(f"[known-good] saved for node={node!r} → {path}")


def load_known_good(node: str) -> Optional[Dict[str, Any]]:
    path = known_good_path(node)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def validate_repeatable_graphql(url: str, query_text: str, attempts: int = 2) -> Tuple[bool, str]:
    """
    Stage 2: send the same query ``attempts`` times; all must pass
    ``is_successful_graphql_response`` (HTTP 200, empty errors, non-empty data).
    """
    headers = graphql_request_headers()
    for i in range(attempts):
        print(f"[validate] identical GraphQL POST attempt {i + 1}/{attempts}")
        try:
            r = requests.post(
                url,
                headers=headers,
                json={"query": query_text},
                timeout=10,
            )
        except requests.RequestException as e:
            return False, f"request_error_attempt_{i+1}:{e!r}"
        try:
            body = r.json()
        except ValueError:
            body = {"error": "invalid_json", "raw": r.text[:500]}
        payload = {
            "response_status": r.status_code,
            "response_body": body,
        }
        if not is_successful_graphql_response(payload):
            return False, f"not_successful_attempt_{i+1}_status_{r.status_code}"
    return True, "repeatable_ok"
