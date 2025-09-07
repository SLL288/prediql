from config import Config
import json
import os 


# ---- Coverage tracking (minimal) ----


COVERAGE_STATE_PATH = os.path.join(Config.OUTPUT_DIR, "coverage_state.json")

def _load_coverage_state():
    """Load { node: [path, ...], ... } from disk into { node: set(paths) }."""
    try:
        if os.path.exists(COVERAGE_STATE_PATH) and os.path.getsize(COVERAGE_STATE_PATH) > 0:
            with open(COVERAGE_STATE_PATH, "r", encoding="utf-8") as f:
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
        with open(COVERAGE_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
    except Exception as e:
        print(f"⚠️ coverage save error: {e}")

def _extract_last_payload_text(jsonfile_path: str) -> str | None:
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
            if "query" in last and isinstance(last["query"], str):
                return last["query"]
            if "mutation" in last and isinstance(last["mutation"], str):
                return last["mutation"]
    except Exception as e:
        print(f"⚠️ read payload error: {e}")
    return None

def _graphql_field_paths(doc: str) -> set[str]:
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
    jsonfile_path = COVERAGE_STATE_PATH
    """
    Returns 1 if the last payload adds at least one NEW field path for this node; else 0.
    Updates persistent coverage state at pred iql-output/coverage_state.json
    """
    state = _load_coverage_state()
    node_set = state.get(node, set())

    gql_text = _extract_last_payload_text(jsonfile_path)
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
