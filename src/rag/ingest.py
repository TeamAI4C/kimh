"""
Phase 1 – Ingest CVE corpus into ChromaDB vector store.

Expects each CVE entry as a JSON file in `data/cve_corpus/` with schema:
{
  "cve_id": "CVE-2023-XXXX",
  "vuln_type": "use-after-free",           # or "buffer-overflow", etc.
  "root_cause": "Free-text description …",
  "vulnerable_code": "char *buf = malloc(…); …",
  "patched_code":    "char *buf = malloc(…); …",
  "diff":            "--- a/src/foo.c\\n+++ b/src/foo.c\\n@@ …",
  "source_file":     "src/foo.c",
  "cwe_id":          "CWE-416"
}
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import chromadb

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Chunking helpers
# ---------------------------------------------------------------------------

def _chunk_text(text: str, chunk_size: int = 1200, overlap: int = 200) -> list[str]:
    """Slide a window over *text* and return overlapping chunks."""
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks


def _build_document(entry: dict[str, Any]) -> str:
    """Flatten a CVE JSON entry into a single text document for embedding."""
    parts = [
        f"CVE: {entry.get('cve_id', 'N/A')}",
        f"Type: {entry.get('vuln_type', 'N/A')}",
        f"CWE: {entry.get('cwe_id', 'N/A')}",
        f"File: {entry.get('source_file', 'N/A')}",
        "",
        "=== Root Cause ===",
        entry.get("root_cause", ""),
        "",
        "=== Vulnerable Code ===",
        entry.get("vulnerable_code", ""),
        "",
        "=== Patched Code ===",
        entry.get("patched_code", ""),
        "",
        "=== Diff ===",
        entry.get("diff", ""),
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class VulnKnowledgeBase:
    """Manages the ChromaDB-backed RAG knowledge base for vulnerability data."""

    def __init__(
        self,
        persist_directory: str = "data/vectordb",
        collection_name: str = "vuln_patches",
        embedding_model: str = "text-embedding-3-large",
        chunk_size: int = 1200,
        chunk_overlap: int = 200,
        openai_api_key: str | None = None,
    ):
        self.persist_directory = persist_directory
        self.collection_name = collection_name
        self.embedding_model = embedding_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self._openai_api_key = openai_api_key

        # Lazy-init so we can swap in a mock for testing
        self._client: chromadb.ClientAPI | None = None
        self._collection: chromadb.Collection | None = None
        self._embed_fn = None

    # -- ChromaDB setup -----------------------------------------------------

    def _get_client(self) -> chromadb.ClientAPI:
        if self._client is None:
            persist_dir = Path(self.persist_directory)
            persist_dir.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=str(persist_dir))
        return self._client

    def _get_embedding_function(self):
        """Return an OpenAI-based embedding function for ChromaDB."""
        if self._embed_fn is None:
            from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

            api_key = self._openai_api_key or os.environ.get("OPENAI_API_KEY")
            if not api_key:
                raise RuntimeError(
                    "OpenAI API key not found. Set OPENAI_API_KEY env var "
                    "or rag.openai_api_key in config/settings.yaml."
                )
            self._embed_fn = OpenAIEmbeddingFunction(
                api_key=api_key,
                model_name=self.embedding_model,
            )
        return self._embed_fn

    def _get_collection(self) -> chromadb.Collection:
        if self._collection is None:
            client = self._get_client()
            self._collection = client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self._get_embedding_function(),
                metadata={"hnsw:space": "cosine"},
            )
        return self._collection

    # -- Ingestion ----------------------------------------------------------

    def ingest_corpus(
        self, corpus_dir: str | Path, batch_size: int = 100,
    ) -> int:
        """Read every *.json in *corpus_dir*, chunk, and upsert into ChromaDB.

        Accumulates chunks into batches of *batch_size* files before upserting
        to reduce the number of embedding API calls.

        Returns the total number of chunks inserted.
        """
        corpus_dir = Path(corpus_dir)
        collection = self._get_collection()
        total_chunks = 0

        batch_ids: list[str] = []
        batch_docs: list[str] = []
        batch_metas: list[dict[str, Any]] = []
        file_count = 0

        json_files = sorted(corpus_dir.glob("*.json"))
        num_files = len(json_files)

        for json_path in json_files:
            try:
                with open(json_path) as f:
                    entry = json.load(f)
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Skipping %s: %s", json_path.name, exc)
                continue

            cve_id = entry.get("cve_id", json_path.stem)
            doc_text = _build_document(entry)
            chunks = _chunk_text(doc_text, self.chunk_size, self.chunk_overlap)

            for i, chunk in enumerate(chunks):
                batch_ids.append(f"{cve_id}__chunk_{i}")
                batch_docs.append(chunk)
                batch_metas.append({
                    "cve_id": cve_id,
                    "vuln_type": entry.get("vuln_type", ""),
                    "cwe_id": entry.get("cwe_id", ""),
                    "source_file": entry.get("source_file", ""),
                    "chunk_index": i,
                })

            file_count += 1

            if file_count % batch_size == 0:
                collection.upsert(
                    ids=batch_ids, documents=batch_docs, metadatas=batch_metas,
                )
                total_chunks += len(batch_ids)
                logger.info(
                    "Ingested %d/%d files (%d chunks so far)",
                    file_count, num_files, total_chunks,
                )
                batch_ids, batch_docs, batch_metas = [], [], []

        # Flush remaining
        if batch_ids:
            collection.upsert(
                ids=batch_ids, documents=batch_docs, metadatas=batch_metas,
            )
            total_chunks += len(batch_ids)

        logger.info(
            "Ingestion complete: %d files, %d total chunks", file_count, total_chunks,
        )
        return total_chunks

    # -- Retrieval ----------------------------------------------------------

    def query(self, vulnerable_code: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Retrieve the *top_k* most relevant past patches for *vulnerable_code*.

        Returns a list of dicts: {document, metadata, distance}.
        """
        collection = self._get_collection()
        results = collection.query(
            query_texts=[vulnerable_code],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )

        hits: list[dict[str, Any]] = []
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            hits.append({"document": doc, "metadata": meta, "distance": dist})

        return hits


# ---------------------------------------------------------------------------
# CLI entry-point for one-off ingestion
# ---------------------------------------------------------------------------

def main() -> None:
    import yaml

    logging.basicConfig(level=logging.INFO)

    with open("config/settings.yaml") as f:
        cfg = yaml.safe_load(f)["rag"]

    kb = VulnKnowledgeBase(
        persist_directory=cfg["vectordb_path"],
        collection_name=cfg["collection_name"],
        embedding_model=cfg["embedding_model"],
        chunk_size=cfg["chunk_size"],
        chunk_overlap=cfg["chunk_overlap"],
        openai_api_key=cfg.get("openai_api_key"),
    )
    kb.ingest_corpus(cfg["corpus_path"])


if __name__ == "__main__":
    main()
