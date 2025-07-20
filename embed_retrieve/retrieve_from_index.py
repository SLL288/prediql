import json
import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


def search(query_text, top_k=5, filter_node_type=None):
    
    INDEX_DIR = "embed_retrieve/faiss_index"
    QUERY_INFO_PATH = "generated_query_info.json"

    # Load index and metadata
    index = faiss.read_index(os.path.join(INDEX_DIR, "index.faiss"))
    with open(os.path.join(INDEX_DIR, "metadata.json")) as f:
        records = json.load(f)

    with open(QUERY_INFO_PATH) as f:
        QUERY_INFO = json.load(f)

    # Load model
    model = SentenceTransformer('all-MiniLM-L6-v2')
    q_emb = model.encode([query_text])
    D, I = index.search(np.array(q_emb).astype('float32'), top_k * 2)

    results = []
    for score, idx in zip(D[0], I[0]):
        record = records[idx]
        if filter_node_type and record["node_type"] != filter_node_type:
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
