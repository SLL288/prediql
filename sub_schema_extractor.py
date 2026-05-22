"""
Operation-local schema fragments for LLM prompts.

Full ``collect_relevant_objects`` graphs can be huge; this module keeps only:
  - the Query/Mutation root field for the current operation,
  - INPUT_OBJECT types reachable from declared arguments,
  - OBJECT/INTERFACE/UNION types within a bounded graph distance of the return type.
"""

from __future__ import annotations

import json
import os
from collections import deque
from typing import Any, Dict, List, Set, Tuple

import yaml

from config import Config


def _unwrap_type(type_str: str) -> str:
    if not type_str:
        return ""
    return type_str.replace("!", "").replace("[", "").replace("]", "")


def _load_object_list() -> Dict[str, Any]:
    path = os.path.join(Config.RUN_LOAD_INTROSPECTION_DIR, "object_list.yml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _slim_type_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Drop noise; keep kind + fields (+ possibleTypes for unions/interfaces)."""
    out: Dict[str, Any] = {"kind": doc.get("kind", "OBJECT")}
    if "possibleTypes" in doc:
        out["possibleTypes"] = doc["possibleTypes"]
    fields = doc.get("fields") or []
    out["fields"] = [{"name": f.get("name"), "type": f.get("type")} for f in fields]
    return out


def _root_operation_slice(
    endpoint: str, source: str, all_objects: Dict[str, Any]
) -> Dict[str, Any]:
    root_name = "Query" if source == "query" else "Mutation"
    root_doc = all_objects.get(root_name)
    if not root_doc:
        return {}
    fields = root_doc.get("fields") or []
    match = next((f for f in fields if f.get("name") == endpoint), None)
    if not match:
        return {}
    return {root_name: {"kind": "OBJECT", "fields": [dict(match)]}}


def _collect_input_closure(
    inputs: Dict[str, Any],
    all_objects: Dict[str, Any],
    budget: int,
) -> Dict[str, Any]:
    """All INPUT_OBJECT types referenced by operation arguments (recursive)."""
    out: Dict[str, Any] = {}
    stack: List[str] = []
    for _arg_name, type_str in (inputs or {}).items():
        base = _unwrap_type(str(type_str))
        if base:
            stack.append(base)

    while stack and len(out) < budget:
        t = stack.pop()
        base = _unwrap_type(t)
        if not base or base in out:
            continue
        doc = all_objects.get(base)
        if not doc or doc.get("kind") != "INPUT_OBJECT":
            continue
        out[base] = _slim_type_doc(doc)
        for f in doc.get("fields") or []:
            nt = _unwrap_type(str(f.get("type", "")))
            if nt and nt in all_objects and all_objects[nt].get("kind") == "INPUT_OBJECT":
                stack.append(nt)
    return out


def _bfs_output_types(
    output: str,
    all_objects: Dict[str, Any],
    max_distance: int,
    max_types: int,
) -> List[str]:
    """BFS over OBJECT/INTERFACE/UNION references starting at the operation return type."""
    root = _unwrap_type(str(output))
    if not root or root not in all_objects:
        return []

    ordered: List[str] = []
    enqueued: Set[str] = {root}
    q: deque[Tuple[str, int]] = deque([(root, 0)])

    while q and len(ordered) < max_types:
        t, d = q.popleft()
        doc = all_objects.get(t)
        if not doc:
            continue
        kind = doc.get("kind", "OBJECT")
        if kind not in ("OBJECT", "INTERFACE", "UNION"):
            continue
        ordered.append(t)
        if d >= max_distance:
            continue
        for f in doc.get("fields") or []:
            nt = _unwrap_type(str(f.get("type", "")))
            if not nt or nt not in all_objects:
                continue
            nk = all_objects[nt].get("kind", "OBJECT")
            if nk in ("OBJECT", "INTERFACE", "UNION"):
                if nt not in enqueued:
                    enqueued.add(nt)
                    q.append((nt, d + 1))
    return ordered


def build_llm_schema_text(
    endpoint: str,
    source: str,
    inputs: Dict[str, Any],
    output: str,
    full_relevant_objects: Dict[str, Any],
    selection_depth: int,
) -> str:
    """
    Return JSON text for the LLM schema block.

    If ``SUBSCHEMA_ENABLED`` is false or the full graph is already small, dumps
    ``full_relevant_objects`` (same information as before extraction).
    """
    if not getattr(Config, "SUBSCHEMA_ENABLED", True):
        return json.dumps(full_relevant_objects, indent=2, ensure_ascii=False)

    threshold = int(getattr(Config, "SUBSCHEMA_FULL_THRESHOLD_TYPES", 45))
    if len(full_relevant_objects) <= threshold:
        return json.dumps(full_relevant_objects, indent=2, ensure_ascii=False)

    all_objects = _load_object_list()
    max_types = int(getattr(Config, "SUBSCHEMA_MAX_TYPES", 150))
    max_chars = int(getattr(Config, "SUBSCHEMA_MAX_JSON_CHARS", 120_000))

    graph_distance = int(getattr(Config, "SUBSCHEMA_OUTPUT_GRAPH_MAX_DISTANCE", 0))
    if graph_distance <= 0:
        graph_distance = max(2, int(selection_depth) + 2)

    root_part = _root_operation_slice(endpoint, source, all_objects)
    input_part = _collect_input_closure(inputs, all_objects, budget=max_types)
    used = len(root_part) + len(input_part)
    remaining = max(1, max_types - used)

    output_names = _bfs_output_types(output, all_objects, graph_distance, remaining)
    output_part: Dict[str, Any] = {}
    for name in output_names:
        doc = all_objects.get(name)
        if doc:
            output_part[name] = _slim_type_doc(doc)

    merged: Dict[str, Any] = {}
    merged.update(root_part)
    merged.update(input_part)
    merged.update(output_part)

    merged["_subschema_meta"] = {
        "mode": "operation_local",
        "endpoint": endpoint,
        "source": source,
        "output_root": _unwrap_type(str(output)),
        "graph_max_distance": graph_distance,
        "types_included": len(merged) - 1,
        "full_graph_type_count": len(full_relevant_objects),
    }

    text = json.dumps(merged, indent=2, ensure_ascii=False)
    if len(text) <= max_chars:
        return text

    merged["_subschema_meta"]["truncated_by_chars"] = True
    merged["_subschema_meta"]["original_chars"] = len(text)
    drop_candidates = [
        k
        for k in merged
        if k not in root_part and k not in input_part and k != "_subschema_meta"
    ]
    for drop in reversed(drop_candidates):
        del merged[drop]
        text = json.dumps(merged, indent=2, ensure_ascii=False)
        if len(text) <= max_chars:
            merged["_subschema_meta"]["final_chars"] = len(text)
            return text

    merged["_subschema_meta"]["final_chars"] = len(text)
    if len(text) > max_chars:
        text = text[: max_chars - 80] + "\n/* ... sub-schema JSON truncated ... */\n"
    return text
