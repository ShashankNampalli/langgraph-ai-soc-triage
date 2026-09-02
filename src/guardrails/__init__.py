"""Input/output safety rails for remediation actions."""

from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?prior",
    r"you\s+are\s+now",
    r"system\s*:\s*",
]

DISALLOWED_ACTIONS = [
    r"rm\s+-rf\s+/",
    r"format\s+c:",
    r"drop\s+database",
    r"delete\s+all\s+users",
]


def check_alert_input(description: str) -> tuple[bool, str]:
    """Reject obvious prompt-injection patterns in alert text."""
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, description, re.IGNORECASE):
            return False, f"Blocked prompt-injection pattern: {pattern}"
    return True, ""


def validate_remediation_actions(actions: list[str]) -> tuple[bool, str]:
    """Block disallowed destructive commands in remediation output."""
    for action in actions:
        for pattern in DISALLOWED_ACTIONS:
            if re.search(pattern, action, re.IGNORECASE):
                return False, f"Blocked disallowed action matching: {pattern}"
    return True, ""
