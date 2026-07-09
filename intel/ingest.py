"""Chunk + embed intel records into Chroma (issue #16).

One record = one chunk — ATT&CK technique descriptions, CVE descriptions, and CERT-In
advisory summaries are all short enough that further splitting would only hurt retrieval
precision. Uses Chroma's bundled local embedding (ONNX MiniLM) — no API key required,
independent of which LLM provider intel/llm.py picks.
"""

from __future__ import annotations

import chromadb
from chromadb.utils import embedding_functions

COLLECTION_NAME = "intel"
_EMBED_FN = embedding_functions.DefaultEmbeddingFunction()


def build_collection(records: list[dict], persist_dir: str | None):
    """persist_dir=None -> in-memory (tests); a path -> persisted on disk (real use)."""
    client = chromadb.PersistentClient(path=persist_dir) if persist_dir else chromadb.Client()
    collection = client.get_or_create_collection(COLLECTION_NAME, embedding_function=_EMBED_FN)
    if collection.count() == 0 and records:
        collection.add(
            ids=[r["id"] for r in records],
            documents=[f"{r['name']}: {r['description']}" for r in records],
            metadatas=[{"source_type": r["source_type"], "name": r["name"]} for r in records],
        )
    return collection


def query(collection, text: str, n_results: int = 3) -> list[dict]:
    res = collection.query(query_texts=[text], n_results=n_results)
    out = []
    for i, doc_id in enumerate(res["ids"][0]):
        meta = res["metadatas"][0][i]
        out.append({
            "id": doc_id,
            "name": meta["name"],
            "description": res["documents"][0][i].split(": ", 1)[-1],
            "source_type": meta["source_type"],
            "distance": res["distances"][0][i],
        })
    return out
