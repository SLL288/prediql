import json
import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


def embed_real_data():
    REAL_DATA_PATH = "real_data.json"
    INDEX_DIR = "embed_retrieve/faiss_index"

    os.makedirs(INDEX_DIR, exist_ok=True)

    # 1️⃣ Load data
    with open(REAL_DATA_PATH) as f:
        records = json.load(f)

    texts = [r["text"] for r in records]

    print(f"✅ Loaded {len(texts)} texts for embedding.")

    # 2️⃣ Embed
    model = SentenceTransformer('all-MiniLM-L6-v2')
    embeddings = model.encode(texts, show_progress_bar=True)

    print(f"✅ Embedding shape: {embeddings.shape}")

    # 3️⃣ Build FAISS index
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(np.array(embeddings).astype('float32'))

    faiss.write_index(index, os.path.join(INDEX_DIR, "index.faiss"))

    # 4️⃣ Save metadata
    with open(os.path.join(INDEX_DIR, "metadata.json"), "w") as f:
        json.dump(records, f, indent=2)

    print(f"✅ Saved FAISS index and metadata for {len(records)} records!")
