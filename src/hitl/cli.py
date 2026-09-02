"""CLI human-in-the-loop approval."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel

console = Console()


async def request_cli_approval(payload: dict[str, Any]) -> dict[str, str]:
    """Prompt analyst for approve/reject in the terminal."""
    gate = payload.get("gate", "unknown")
    reasons = payload.get("reasons", [])
    alert_title = payload.get("alert_title", "Unknown alert")

    body = f"Gate: {gate}\nAlert: {alert_title}\n"
    if reasons:
        body += "Reasons:\n" + "\n".join(f"  - {r}" for r in reasons)

    console.print(Panel(body, title="Human Approval Required", border_style="yellow"))
    response = console.input("[bold]Approve? [y/N]: [/bold]").strip().lower()
    decision = "approve" if response in ("y", "yes") else "reject"
    return {"decision": decision, "gate": gate}
