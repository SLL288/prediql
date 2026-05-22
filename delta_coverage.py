from config import Config, run_node_dir
import json
import os
from typing import Union, Optional, Set 


# ---- Coverage tracking (minimal) ----
# Path must be resolved at use time: Config.OUTPUT_DIR is set after import (configure_run_artifacts).


def _coverage_state_path() -> str:
    return os.path.join(Config.OUTPUT_DIR, "coverage_state.json")


def _load_coverage_state():
    """Load { node: [path, ...], ... } from disk into { node: set(paths) }."""
    path = _coverage_state_path()
    try:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {k: set(v) for k, v in data.items()}
    except Exception as e:
        print(f"⚠️ coverage load error: {e}")
    return {}

def _save_coverage_state(state):
    """Persist { node: set(paths) } as lists."""
    try:
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
        serializable = {k: sorted(list(v)) for k, v in state.items()}
        with open(_coverage_state_path(), "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        print(f"⚠️ coverage save error: {e}")

def _extract_last_payload_text(jsonfile_path: str) -> Optional[str]:
    """
    Returns the GraphQL text of the LAST entry in llama_queries.json.
    Supports entries shaped like {"query": "..."} or {"mutation": "..."}.
    """
    try:
        if not (os.path.exists(jsonfile_path) and os.path.getsize(jsonfile_path) > 0):
            return None
        with open(jsonfile_path, "r", encoding="utf-8") as f:
            arr = json.load(f)
        if not isinstance(arr, list) or not arr:
            return None
        last = arr[-1]
        if isinstance(last, dict):
            if "query" in last:
                q = last["query"]
                if isinstance(q, str):
                    return q
                if isinstance(q, dict) and isinstance(q.get("query"), str):
                    return q["query"]
            if "mutation" in last:
                m = last["mutation"]
                if isinstance(m, str):
                    return m
                if isinstance(m, dict) and isinstance(m.get("query"), str):
                    return m["query"]
    except Exception as e:
        print(f"⚠️ read payload error: {e}")
    return None

def _graphql_field_paths(doc: str) -> Set[str]:
    """
    Very lightweight GraphQL field path extractor.
    Not a full parser; good enough to signal coverage progress.
    Produces dotted paths like: user, user.friends, user.friends.name
    """
    import re
    # remove comments
    doc = re.sub(r'#.*', '', doc)
    # tokens = identifiers and braces
    tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_]*|[{}:]', doc)

    KEYWORDS = {'query', 'mutation', 'subscription', 'fragment', 'on', 'true', 'false', 'null'}
    paths = set()
    stack = []
    i = 0
    while i < len(tokens):
        t = tokens[i]

        if t == '{':
            i += 1
            continue
        if t == '}':
            if stack:
                stack.pop()
            i += 1
            continue

        # identifier (potential field or alias)
        if re.match(r'^[A-Za-z_]\w*$', t) and t not in KEYWORDS:
            # detect alias: aliasName : realField
            # lookahead for ":"; if yes, next identifier is the real field
            if i + 1 < len(tokens) and tokens[i+1] == ':':
                # skip alias token and colon, take next identifier as field name if present
                if i + 2 < len(tokens) and re.match(r'^[A-Za-z_]\w*$', tokens[i+2]) and tokens[i+2] not in KEYWORDS:
                    field = tokens[i+2]
                    stack.append(field)
                    paths.add(".".join(stack))
                    # if the next significant token after field is not "{", pop immediately (scalar)
                    j = i + 3
                    while j < len(tokens) and tokens[j] not in ('{', '}'):
                        j += 1
                    if j >= len(tokens) or tokens[j] != '{':
                        stack.pop()
                    i = i + 3
                    continue
            # normal field
            field = t
            stack.append(field)
            paths.add(".".join(stack))
            # if no nested selection follows, pop immediately
            j = i + 1
            while j < len(tokens) and tokens[j] not in ('{', '}'):
                j += 1
            if j >= len(tokens) or tokens[j] != '{':
                stack.pop()
            i += 1
            continue

        i += 1

    return paths

def compute_delta_coverage(node: str) -> int:
    """
    Returns 1 if the last payload adds at least one NEW field path for this node; else 0.
    Reads the latest GraphQL text from ``OUTPUT_DIR/nodes/{node}/llama_queries.json`` and
    updates persistent coverage state at ``coverage_state.json`` under OUTPUT_DIR.
    """
    state = _load_coverage_state()
    node_set = state.get(node, set())

    llama_path = os.path.join(run_node_dir(node), "llama_queries.json")
    gql_text = _extract_last_payload_text(llama_path)
    if not gql_text:
        return 0

    new_paths = _graphql_field_paths(gql_text)
    unseen = new_paths - node_set
    if unseen:
        node_set |= unseen
        state[node] = node_set
        _save_coverage_state(state)
        # Optional debug
        try:
            example = next(iter(unseen))
            print(f"🧩 coverage +{len(unseen)} new paths for {node} (e.g., {example})")
        except StopIteration:
            pass
        return 1
    return 0
# ---- end coverage tracking ----
