"""Chunk + embed intel records into Chroma (issue #16).

One record = one chunk — ATT&CK technique descriptions, CVE descriptions, and CERT-In
advisory summaries are all short enough that further splitting would only hurt retrieval
precision. Uses Chroma's bundled local embedding (ONNX MiniLM) — no API key required,
independent of which LLM provider intel/llm.py picks.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions

COLLECTION_NAME = "intel"
_EMBED_FN = embedding_functions.DefaultEmbeddingFunction()

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "intel"
DEFAULT_PERSIST_DIR = str(DATA_DIR / "chroma")
_SOURCE_FILES = ("attack.json", "cve.json", "certin.json")


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


def load_records(data_dir=DATA_DIR) -> list[dict]:
    """Read the JSON files fetch_sources.py wrote (attack/cve/certin) and concatenate them.
    A missing file is skipped, not fatal — e.g. a run with no CVE keywords."""
    records: list[dict] = []
    for fname in _SOURCE_FILES:
        path = Path(data_dir) / fname
        if path.exists():
            records.extend(json.loads(path.read_text()))
    return records


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


def main() -> None:
    """Populate the persistent Chroma collection from the fetched intel JSON.

    This is the ingest half of #16 — the runnable bridge between `python -m intel.fetch_sources`
    (writes data/intel/*.json) and ENRICH_MODE=live (opens data/intel/chroma). Without it the
    collection is never seeded and the live agent honestly returns UNKNOWN for everything.
        python -m intel.fetch_sources   # fetch sources -> data/intel/*.json
        python -m intel.ingest          # embed them    -> data/intel/chroma
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=str(DATA_DIR))
    ap.add_argument("--persist-dir", default=DEFAULT_PERSIST_DIR)
    args = ap.parse_args()

    records = load_records(args.data_dir)
    if not records:
        raise SystemExit(
            f"no intel JSON found in {args.data_dir} — run `python -m intel.fetch_sources` first"
        )
    collection = build_collection(records, persist_dir=args.persist_dir)
    print(f"ingested {len(records)} records -> {args.persist_dir} "
          f"(collection count={collection.count()})")


if __name__ == "__main__":
    main()
