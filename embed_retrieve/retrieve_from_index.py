import json
import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

from config import Config


class MissingEmbeddingIndexError(RuntimeError):
    """Raised when ``index.faiss`` / ``metadata.json`` are absent (expected before first ``embed_real_data``)."""


def embedding_index_paths():
    """Return ``(index_faiss_path, metadata_json_path)`` for the current run's embed dir."""
    d = Config.EMBED_INDEX_DIR
    return (
        os.path.join(d, "index.faiss"),
        os.path.join(d, "metadata.json"),
    )


def embedding_index_ready() -> bool:
    """True if both FAISS index files exist (embedding step has run at least once)."""
    ip, mp = embedding_index_paths()
    return os.path.isfile(ip) and os.path.isfile(mp)


def _norm_op_name(name: str) -> str:
    s = (name or "").strip().lower()
    if s.endswith("ies") and len(s) > 3:
        return s[:-3] + "y"
    if s.endswith("es") and len(s) > 2:
        return s[:-2]
    if s.endswith("s") and len(s) > 1:
        return s[:-1]
    return s


def _operation_target_from_query_text(query_text: str) -> str:
    # main.py passes query text in the form: "<operation>, input: ...".
    return (str(query_text or "").split(",", 1)[0]).strip().lower()


def _operation_match_bucket(candidate_op: str, target_op: str) -> int:
    """
    Lower is better.
      0: exact operation match
      1: same normalized singular/plural stem (continent vs continents)
      2: no operation-name match
    """
    c = (candidate_op or "").strip().lower()
    t = (target_op or "").strip().lower()
    if not t or not c:
        return 2
    if c == t:
        return 0
    if _norm_op_name(c) == _norm_op_name(t):
        return 1
    return 2


def search(query_text, top_k=5, filter_node_type=None):
    QUERY_INFO_PATH = Config.GENERATED_QUERY_INFO_JSON

    index_path, meta_path = embedding_index_paths()
    if not embedding_index_ready():
        raise MissingEmbeddingIndexError(
            "Embedding index not built yet (normal on early rounds before real_data.json is embedded). "
            "Snippet retrieval is skipped until embed_retrieve/faiss_index contains index.faiss and metadata.json."
        )

    # Load index and metadata
    try:
        index = faiss.read_index(index_path)
    except Exception as e:
        raise MissingEmbeddingIndexError(
            f"Could not read embedding index at {index_path} ({e}). "
            "Try re-running embed_real_data after flatten_real_data."
        ) from e
    with open(meta_path, encoding="utf-8") as f:
        records = json.load(f)

    with open(QUERY_INFO_PATH, encoding="utf-8") as f:
        QUERY_INFO = json.load(f)

    # Load model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    q_emb = model.encode([query_text])
    target_op = _operation_target_from_query_text(query_text)
    fetch_k = max(top_k * 8, 40)
    D, I = index.search(np.array(q_emb).astype('float32'), fetch_k)

    candidates = []
    for score, idx in zip(D[0], I[0]):
        if idx < 0 or idx >= len(records):
            continue
        record = records[idx]
        if filter_node_type and record["node_type"] != filter_node_type:
            continue
        op = str(record.get("query_name", "") or "")
        bucket = _operation_match_bucket(op, target_op)
        candidates.append((bucket, float(score), op, record))

    # Prefer operation-matching examples first, then nearest FAISS distance.
    candidates.sort(key=lambda x: (x[0], x[1]))

    # Keep diversity so one heavy operation (e.g., countries) does not flood context.
    max_per_op = 2
    per_op = {}
    results = []
    for _bucket, score, op, record in candidates:
        key = (op or "").strip().lower() or "_"
        n = per_op.get(key, 0)
        if n >= max_per_op:
            continue
        per_op[key] = n + 1
        results.append((score, record))
        if len(results) >= top_k:
            break

    # Fallback fill (if diversity cap was too strict).
    if len(results) < top_k:
        seen_ids = {id(r[1]) for r in results}
        for _bucket, score, _op, record in candidates:
            if id(record) in seen_ids:
                continue
            results.append((score, record))
            if len(results) >= top_k:
                break
    return results

# --- Example usage ---

# query = "Star Wars films featuring Luke Skywalker"
# node_filter = "Film"  # Optional node type filter

# results = search(query, top_k=5, filter_node_type=node_filter)

# for i, (score, record) in enumerate(results, 1):
#     print("=" * 40)
#     print(f"Result {i} (Score {score:.2f})")
#     print(f"Source: {record['source']}")
#     print(f"Query Name: {record['query_name']}")
#     print(f"Node Type: {record['node_type']}")
#     print("\nText:\n")
#     print(record["text"])
