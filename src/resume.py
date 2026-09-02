"""Resume a paused triage run after human approval."""

from __future__ import annotations

import argparse
import asyncio

from .graph import resume_triage


async def resume_run(thread_id: str, decision: str) -> None:
    result = await resume_triage(thread_id, decision)
    print(f"Run {thread_id} resumed with decision={decision}")
    print(f"Status: {result.get('status', 'unknown')}")
    print(f"Decision: {result.get('human_decision', '')}")


def main():
    parser = argparse.ArgumentParser(description="Resume a paused HITL triage run")
    parser.add_argument("--run-id", required=True, help="Thread ID of the paused run")
    parser.add_argument(
        "--decision",
        required=True,
        choices=["approve", "reject"],
        help="Human approval decision",
    )
    args = parser.parse_args()
    asyncio.run(resume_run(args.run_id, args.decision))


if __name__ == "__main__":
    main()
