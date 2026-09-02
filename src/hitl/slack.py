"""Slack webhook notifications for human approval requests."""

from __future__ import annotations

import os
from typing import Any

import httpx
from rich.console import Console

from .cli import request_cli_approval

console = Console()


async def request_slack_approval(payload: dict[str, Any]) -> dict[str, str]:
    """Post approval request to Slack, then fall back to CLI for the decision."""
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
    gate = payload.get("gate", "unknown")
    alert_title = payload.get("alert_title", "Unknown alert")
    reasons = payload.get("reasons", [])

    if webhook_url:
        text = (
            f":warning: *Approval required — Gate {gate}*\n"
            f"*Alert:* {alert_title}\n"
        )
        if reasons:
            text += "*Reasons:*\n" + "\n".join(f"• {r}" for r in reasons)
        text += "\n_Resume via CLI: `python -m src.resume --run-id <id> --decision approve`_"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(webhook_url, json={"text": text})
            console.print("[green]Slack notification sent.[/green]")
        except httpx.HTTPError as exc:
            console.print(f"[yellow]Slack webhook failed: {exc}[/yellow]")

    return await request_cli_approval(payload)
