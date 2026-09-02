"""Demo runner showing the triage system in action."""

from __future__ import annotations

import argparse
import asyncio

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from .graph import TriageState, run_triage
from .models import SecurityAlert
from .scenarios import SAMPLE_ALERTS

console = Console()


def print_alert(alert: SecurityAlert) -> None:
    console.print(
        Panel(
            f"[bold]{alert.title}[/bold]\n\n"
            f"[dim]Source:[/dim] {alert.source}\n"
            f"[dim]Resource:[/dim] {alert.affected_resource}\n"
            f"[dim]Time:[/dim] {alert.timestamp}\n\n"
            f"{alert.description}\n\n"
            f"[dim]Indicators:[/dim] {', '.join(alert.raw_indicators)}",
            title=f"Alert {alert.alert_id}",
            border_style="red",
        )
    )


def print_result(state: dict) -> None:
    classification = state.get("classification")
    investigation = state.get("investigation")
    remediation = state.get("remediation")

    if classification:
        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "dim",
        }
        color = severity_colors.get(classification.severity.value, "white")
        console.print("\n[bold]Classification:[/bold]")
        console.print(f"  Severity: [{color}]{classification.severity.value.upper()}[/{color}]")
        console.print(f"  Category: {classification.category.value}")
        console.print(f"  Confidence: {classification.confidence:.0%}")
        console.print(f"  Reasoning: {classification.reasoning}")

    if investigation:
        console.print("\n[bold]Investigation:[/bold]")
        console.print(f"  Scope: {investigation.affected_scope}")
        console.print(f"  Vector: {investigation.attack_vector}")
        for finding in investigation.findings:
            console.print(f"  - {finding}")
        if investigation.requires_escalation:
            console.print(
                f"  [red bold]GATE #1 — ESCALATION: {investigation.escalation_reason}[/red bold]"
            )

    if remediation:
        console.print("\n[bold]Remediation:[/bold]")
        console.print("  [underline]Immediate:[/underline]")
        for action in remediation.immediate_actions:
            console.print(f"    > {action}")
        console.print("  [underline]Long-term:[/underline]")
        for fix in remediation.long_term_fixes:
            console.print(f"    > {fix}")
        if remediation.requires_human_approval:
            console.print(
                f"  [yellow]GATE #2 — Needs approval: {remediation.approval_reason}[/yellow]"
            )

    status = state.get("status", "unknown")
    decision = state.get("human_decision", "")
    status_color = "red" if status in ("closed",) else "green" if status == "auto_resolved" else "yellow"
    console.print(f"\n[bold]Status:[/bold] [{status_color}]{status}[/{status_color}]")
    if decision:
        console.print(f"  {decision}")
    console.print("=" * 60)


async def run_demo(alert_index: int | None = None, auto_approve: bool = False) -> None:
    alerts = [SAMPLE_ALERTS[alert_index]] if alert_index is not None else SAMPLE_ALERTS

    console.print(
        "\n[bold cyan]LangGraph AI SOC Triage — Multi-Agent Demo[/bold cyan]"
    )
    console.print(f"Processing {len(alerts)} alert(s)...\n")

    for i, alert in enumerate(alerts):
        print_alert(alert)

        initial_state: TriageState = {
            "alert": alert,
            "classification": None,
            "investigation": None,
            "remediation": None,
            "human_decision": "",
            "status": "pending",
        }

        console.print(
            "[dim]Running: classify -> investigate -> [gate #1] -> remediate -> [gate #2] -> execute[/dim]"
        )
        result = await run_triage(
            initial_state,
            thread_id=f"demo-{alert.alert_id}",
            auto_approve=auto_approve,
        )
        print_result(result)


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="LangGraph AI SOC Triage demo")
    parser.add_argument("--alert", type=int, default=None, help="Alert index (0-based)")
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve all HITL gates (non-interactive)",
    )
    args = parser.parse_args()
    asyncio.run(run_demo(alert_index=args.alert, auto_approve=args.auto_approve))


if __name__ == "__main__":
    main()
