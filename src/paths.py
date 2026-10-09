"""Repository-relative path helpers (Cloud-safe when cwd differs)."""

from __future__ import annotations

from pathlib import Path

from .config import get_setting


def project_root() -> Path:
    """Return the repository root (parent of the src package)."""
    return Path(__file__).resolve().parent.parent


def resolve_under_root(*parts: str) -> Path:
    """Join path parts under the project root."""
    return project_root().joinpath(*parts)


def default_db_path() -> Path:
    """Resolve SQLITE_DB / DATA_DIR relative to the project root when needed."""
    env_path = get_setting("SQLITE_DB")
    if not env_path:
        data_dir = get_setting("DATA_DIR", "data") or "data"
        env_path = str(Path(data_dir) / "triage.db")

    path = Path(env_path)
    if not path.is_absolute():
        path = project_root() / path
    return path


def playbooks_json_path() -> Path:
    return resolve_under_root("data", "playbooks.json")
