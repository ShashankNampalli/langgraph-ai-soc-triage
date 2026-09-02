"""Tests for scenario routing expectations with offline agents."""

import os

import pytest

from src.graph import run_triage, TriageState
from src.offline import offline_classify, offline_investigate
from src.scenarios import SAMPLE_ALERTS, SCENARIO_EXPECTATIONS


@pytest.fixture(autouse=True)
def offline_mode():
    os.environ["OFFLINE_MODE"] = "true"
    yield
    os.environ.pop("OFFLINE_MODE", None)


@pytest.mark.asyncio
@pytest.mark.parametrize("alert_id", list(SCENARIO_EXPECTATIONS.keys()))
async def test_scenario_routing(alert_id: str):
    alert = next(a for a in SAMPLE_ALERTS if a.alert_id == alert_id)
    expected = SCENARIO_EXPECTATIONS[alert_id]

    classification = offline_classify(alert)
    investigation = offline_investigate(alert, classification)

    gate1_fires = investigation.requires_escalation
    assert gate1_fires == expected["gate1"], (
        f"{alert_id}: expected gate1={expected['gate1']}, got {gate1_fires}"
    )

    initial_state: TriageState = {
        "alert": alert,
        "classification": None,
        "investigation": None,
        "remediation": None,
        "human_decision": "",
        "status": "pending",
    }

    result = await run_triage(
        initial_state,
        thread_id=f"test-{alert_id}",
        auto_approve=True,
    )

    if expected["gate1"] or expected["gate2"]:
        assert result["status"] in ("executed", "remediation_approved", "investigation_approved", "executed")
    else:
        assert result["status"] == "auto_resolved"


@pytest.mark.asyncio
async def test_ransomware_triggers_both_gates():
    alert = next(a for a in SAMPLE_ALERTS if a.alert_id == "ALT-2026-0850")
    classification = offline_classify(alert)
    investigation = offline_investigate(alert, classification)

    assert classification.severity.value == "critical"
    assert investigation.requires_escalation is True


@pytest.mark.asyncio
async def test_vuln_scan_auto_resolves():
    alert = next(a for a in SAMPLE_ALERTS if a.alert_id == "ALT-2026-0852")

    initial_state: TriageState = {
        "alert": alert,
        "classification": None,
        "investigation": None,
        "remediation": None,
        "human_decision": "",
        "status": "pending",
    }

    result = await run_triage(
        initial_state,
        thread_id="test-vuln-scan",
        auto_approve=True,
    )
    assert result["status"] == "auto_resolved"
