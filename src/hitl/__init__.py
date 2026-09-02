"""Human-in-the-loop approval backends."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()


def get_hitl_backend() -> str:
    return os.getenv("HITL_BACKEND", "cli").lower()


async def request_approval(payload: dict[str, Any]) -> dict[str, str]:
    """Route approval request to configured backend."""
    backend = get_hitl_backend()
    if backend == "slack":
        from .slack import request_slack_approval

        return await request_slack_approval(payload)
    from .cli import request_cli_approval

    return await request_cli_approval(payload)
