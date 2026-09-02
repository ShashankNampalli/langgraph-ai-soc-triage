"""Ingest incident response playbooks from Hugging Face into SQLite + JSON."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
PLAYBOOKS_JSON = DATA_DIR / "playbooks.json"
HF_DATASET = "darkknight25/Incident_Response_Playbook_Dataset"
COLLECTION_NAME = os.getenv("QDRANT_COLLECTION", "incident_playbooks")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")

CATEGORY_MAP = {
    "ransomware": "malware",
    "phishing": "unauthorized_access",
    "data breach": "data_exfiltration",
    "data exfiltration": "data_exfiltration",
    "malware": "malware",
    "unauthorized access": "unauthorized_access",
    "lateral movement": "lateral_movement",
    "ddos": "anomalous_behavior",
    "insider threat": "unauthorized_access",
    "denial of service": "anomalous_behavior",
    "sql injection": "anomalous_behavior",
}


def _load_jsonl_from_hf() -> list[dict]:
    """Load JSONL directly — skips malformed lines the HF datasets loader rejects."""
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=HF_DATASET,
        filename="incident_response_playbook_dataset.jsonl",
        repo_type="dataset",
    )
    rows: list[dict] = []
    skipped = 0
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
    if skipped:
        print(f"Skipped {skipped} malformed JSONL row(s).")
    print(f"Loaded {len(rows)} valid playbook records.")
    return rows


def load_hf_playbooks(max_types: int | None = None) -> list[dict]:
    print(f"Downloading {HF_DATASET} from Hugging Face...")
    rows = _load_jsonl_from_hf()

    documents: list[dict] = []
    seen_types: set[str] = set()

    for row in rows:
        incident_type = str(row.get("incident_type", "")).lower().strip()
        if not incident_type or incident_type in seen_types:
            continue
        seen_types.add(incident_type)
        if max_types and len(seen_types) > max_types:
            break

        category = CATEGORY_MAP.get(incident_type, incident_type.replace(" ", "_"))
        steps = row.get("playbook_steps", []) or []
        immediate, investigation, long_term = [], [], []

        for step in steps:
            phase = str(step.get("phase", "")).lower()
            action = str(step.get("action", ""))
            if not action:
                continue
            if "contain" in phase or "initial" in phase:
                immediate.append(action)
            elif "investigat" in phase or "identif" in phase:
                investigation.append(action)
            else:
                long_term.append(action)

        if not immediate and steps:
            immediate = [str(steps[0].get("action", ""))]

        doc = {
            "category": category,
            "title": f"{incident_type.title()} Response",
            "incident_type": incident_type,
            "immediate": immediate[:8],
            "investigation": investigation[:8],
            "long_term": long_term[:8],
            "tactics": str(row.get("tactics_techniques", "")),
            "severity": str(row.get("severity", "")),
            "text": (
                f"Incident type: {incident_type}. "
                f"Severity: {row.get('severity', '')}. "
                f"Tactics: {row.get('tactics_techniques', '')}. "
                f"Vector: {row.get('initial_vector', '')}."
            ),
        }
        for step in steps:
            doc["text"] += (
                f" Phase: {step.get('phase', '')}. Action: {step.get('action', '')}. "
                f"Tools: {step.get('tools', '')}. "
                f"Response time: {step.get('response_time', '')}."
            )
        documents.append(doc)

    return documents


def save_to_sqlite(documents: list[dict]) -> None:
    sys.path.insert(0, str(PROJECT_ROOT))
    from src.db import get_conn, init_db, playbook_count, upsert_playbook

    init_db()
    with get_conn() as conn:
        for doc in documents:
            upsert_playbook(conn, doc)
    print(f"Stored {playbook_count()} playbooks in SQLite ({os.getenv('SQLITE_DB', 'data/triage.db')})")


def save_to_json(documents: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(PLAYBOOKS_JSON, "w", encoding="utf-8") as f:
        json.dump(documents, f, indent=2)
    print(f"Saved {len(documents)} playbooks to {PLAYBOOKS_JSON}")


def index_qdrant(documents: list[dict]) -> None:
    """Optional vector index — skipped if deps or Qdrant unavailable."""
    try:
        from llama_index.core import Document, Settings, VectorStoreIndex
        from llama_index.embeddings.huggingface import HuggingFaceEmbedding
        from llama_index.vector_stores.qdrant import QdrantVectorStore
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, VectorParams
    except ImportError:
        print("Qdrant indexing skipped (llama-index not installed for this Python version).")
        return

    try:
        Settings.embed_model = HuggingFaceEmbedding(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
        client = QdrantClient(url=QDRANT_URL)
        collections = [c.name for c in client.get_collections().collections]
        if COLLECTION_NAME in collections:
            client.delete_collection(COLLECTION_NAME)
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=384, distance=Distance.COSINE),
        )
        llama_docs = [
            Document(
                text=doc["text"],
                metadata={
                    "category": doc["category"],
                    "title": doc["title"],
                    "incident_type": doc.get("incident_type", ""),
                    "immediate": doc.get("immediate", []),
                    "investigation": doc.get("investigation", []),
                    "long_term": doc.get("long_term", []),
                },
            )
            for doc in documents
        ]
        vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION_NAME)
        VectorStoreIndex.from_documents(llama_docs, vector_store=vector_store)
        print(f"Indexed {len(documents)} playbooks in Qdrant ({COLLECTION_NAME})")
    except Exception as exc:
        print(f"Qdrant indexing skipped: {exc}")


def ingest(max_types: int | None = None, qdrant: bool = False) -> list[dict]:
    documents = load_hf_playbooks(max_types=max_types)
    if not documents:
        raise SystemExit("No playbooks loaded from Hugging Face.")

    save_to_json(documents)
    save_to_sqlite(documents)
    if qdrant:
        index_qdrant(documents)
    return documents


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest IR playbooks from Hugging Face")
    parser.add_argument(
        "--max-types",
        type=int,
        default=None,
        help="Max unique incident types (default: all in dataset)",
    )
    parser.add_argument("--qdrant", action="store_true", help="Also index into Qdrant")
    args = parser.parse_args()
    docs = ingest(max_types=args.max_types, qdrant=args.qdrant)
    print(f"Done. {len(docs)} incident types ingested from {HF_DATASET}.")
