"""Settings resolution for local .env and Streamlit Cloud secrets."""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


def get_setting(name: str, default: str | None = None) -> str | None:
    """
    Resolve a setting from (in order):
    1. Environment variables (including values loaded from .env)
    2. Streamlit secrets (local secrets.toml or Streamlit Cloud)
    3. Optional default
    """
    value = os.environ.get(name)
    if value:
        return value

    try:
        import streamlit as st

        secrets = getattr(st, "secrets", None)
        if secrets is not None and name in secrets:
            secret_value = secrets[name]
            if secret_value is not None and str(secret_value).strip():
                return str(secret_value)
    except Exception:
        pass

    return default
