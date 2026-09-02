"""LlamaIndex + Qdrant playbook vector store."""

from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()

COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "incident_playbooks")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")


@lru_cache(maxsize=1)
def _get_index():
    """Lazy-load LlamaIndex vector index from Qdrant."""
    from llama_index.core import Settings, VectorStoreIndex
    from llama_index.embeddings.huggingface import HuggingFaceEmbedding
    from llama_index.vector_stores.qdrant import QdrantVectorStore
    from qdrant_client import QdrantClient

    Settings.embed_model = HuggingFaceEmbedding(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )
    client = QdrantClient(url=QDRANT_URL)
    vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION_NAME)
    return VectorStoreIndex.from_vector_store(vector_store)


def _node_to_playbook(node) -> dict:
    """Convert a retrieved node into the playbook dict format."""
    meta = node.metadata or {}
    return {
        "title": meta.get("title", "Incident Response Playbook"),
        "immediate": meta.get("immediate", []),
        "investigation": meta.get("investigation", []),
        "long_term": meta.get("long_term", []),
        "incident_type": meta.get("incident_type", ""),
        "phase": meta.get("phase", ""),
        "action": meta.get("action", ""),
        "tools": meta.get("tools", ""),
        "response_time": meta.get("response_time", ""),
        "text": node.text,
    }


def get_playbook_from_rag(category: str) -> dict | None:
    """Retrieve best-matching playbook for a category via semantic search."""
    retriever = _get_index().as_retriever(similarity_top_k=1)
    nodes = retriever.retrieve(
        f"incident response playbook for {category.replace('_', ' ')}"
    )
    if not nodes:
        return None
    return _node_to_playbook(nodes[0].node)


def search_playbooks_rag(query: str, top_k: int = 3) -> list[dict]:
    """Semantic search over indexed playbook documents."""
    retriever = _get_index().as_retriever(similarity_top_k=top_k)
    nodes = retriever.retrieve(query)
    results = []
    for i, node_with_score in enumerate(nodes):
        playbook = _node_to_playbook(node_with_score.node)
        category = node_with_score.node.metadata.get("category", "unknown")
        score = node_with_score.score or (top_k - i)
        results.append({"category": category, "playbook": playbook, "score": score})
    return results
