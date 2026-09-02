"""Ingest Advanced_SIEM_Dataset into SQLite (default: 5000 alerts)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.db import alert_count, get_conn, init_db, insert_alert  # noqa: E402

DEFAULT_DATASET = "darkknight25/Advanced_SIEM_Dataset"
DEFAULT_LIMIT = int(os.getenv("SIEM_ALERT_LIMIT", "5000"))


def ingest(limit: int = DEFAULT_LIMIT, dataset: str = DEFAULT_DATASET) -> None:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise SystemExit(
            "Install datasets: pip install -e \".[ui]\""
        ) from exc

    init_db()
    if alert_count() >= limit:
        print(f"Database already has {alert_count()} alerts (>= {limit}). Skipping ingest.")
        return

    print(f"Loading {limit} rows from {dataset}...")
    split = f"train[:{limit}]"
    ds = load_dataset(dataset, split=split)

    with get_conn() as conn:
        for i, row in enumerate(ds, start=1):
            insert_alert(conn, dict(row))
            if i % 500 == 0:
                print(f"  inserted {i}/{limit}")

    print(f"Done. {alert_count()} alerts in database.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ingest SIEM alerts into SQLite")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--dataset", type=str, default=DEFAULT_DATASET)
    args = parser.parse_args()
    ingest(limit=args.limit, dataset=args.dataset)
