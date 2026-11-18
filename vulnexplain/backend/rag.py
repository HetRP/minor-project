"""Repository RAG module using Sentence-Transformers and FAISS.

Chunks repository code by extracted functions, builds dense vector index,
and serializes to backend/store/<scan_id>/ with metadata.
"""

import json
import os
import shutil
from pathlib import Path
from typing import Any
import numpy as np

STORE_BASE_DIR = Path(__file__).resolve().parent / "store"

# Global lazy-loaded embedding model
_EMBED_MODEL = None


def get_embed_model():
    """Lazy load sentence-transformers model."""
    global _EMBED_MODEL
    if _EMBED_MODEL is None:
        try:
            from sentence_transformers import SentenceTransformer
            _EMBED_MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        except Exception as e:
            print(f"Notice: Failed to load sentence-transformers ({e}). Fallback search will be used.")
            _EMBED_MODEL = None
    return _EMBED_MODEL


def build_rag_index(scan_id: str, functions: list[dict[str, Any]]) -> str:
    """Builds and persists FAISS index and chunk metadata for a scan."""
    scan_dir = STORE_BASE_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    metadata = []
    texts = []

    for f in functions:
        meta = {
            "id": f.get("id", ""),
            "file": f.get("file", ""),
            "name": f.get("name", ""),
            "start_line": f.get("start_line", 1),
            "end_line": f.get("end_line", 1),
            "language": f.get("language", ""),
            "text": f"File: {f.get('file', '')} | Function: {f.get('name', '')}\n{f.get('code', '')[:1000]}",
        }
        metadata.append(meta)
        texts.append(meta["text"])

    # Save metadata JSON
    with open(scan_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Build FAISS index if model and faiss available
    embedder = get_embed_model()
    if embedder is not None and texts:
        try:
            import faiss
            embeddings = embedder.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
            dimension = embeddings.shape[1]
            index = faiss.IndexFlatIP(dimension)
            index.add(embeddings.astype(np.float32))
            faiss.write_index(index, str(scan_dir / "index.faiss"))
            return str(scan_dir)
        except Exception as e:
            print(f"Notice: FAISS index creation error ({e}).")

    return str(scan_dir)


def query_rag_index(scan_id: str, query: str, top_k: int = 5) -> list[dict[str, Any]]:
    """Retrieves top-K matching function chunks for a user query."""
    scan_dir = STORE_BASE_DIR / scan_id
    meta_file = scan_dir / "metadata.json"
    index_file = scan_dir / "index.faiss"

    if not meta_file.exists():
        return []

    with open(meta_file, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    if not metadata:
        return []

    embedder = get_embed_model()
    if embedder is not None and index_file.exists():
        try:
            import faiss
            index = faiss.read_index(str(index_file))
            q_emb = embedder.encode([query], convert_to_numpy=True, normalize_embeddings=True)
            k = min(top_k, len(metadata))
            distances, indices = index.search(q_emb.astype(np.float32), k)

            results = []
            for score, idx in zip(distances[0], indices[0]):
                if idx < len(metadata):
                    item = dict(metadata[idx])
                    item["score"] = float(score)
                    results.append(item)
            return results
        except Exception as e:
            print(f"Notice: FAISS retrieval error: {e}")

    # Keyword search fallback
    q_tokens = set(query.lower().split())
    scored = []
    for item in metadata:
        text_lower = item["text"].lower()
        score = sum(1 for t in q_tokens if t in text_lower)
        scored.append((score, item))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [dict(item, score=sc) for sc, item in scored[:top_k]]
