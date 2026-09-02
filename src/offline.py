"""Offline deterministic agent outputs for tests and CI."""

from __future__ import annotations

from .models import (
    AlertCategory,
    Classification,
    Investigation,
    Remediation,
    SecurityAlert,
    Severity,
)


def _severity_from_alert(alert: SecurityAlert) -> Severity:
    # ponytail: keyword heuristics, swap for LLM classify when offline mode is off
    text = f"{alert.title} {alert.description}".lower()
    # Benign / blocked noise — check before threat keywords in negated context
    if any(
        k in text
        for k in (
            "vulnerability scan",
            "no successful exploitation",
            "no exploitation",
            "all requests blocked",
        )
    ):
        return Severity.LOW
    if any(k in text for k in ("ransomware", "exfiltration", "tor exit", "c2 beacon", "pii")):
        return Severity.CRITICAL
    if any(k in text for k in ("lateral movement via", "rdp to", "brute force", "malware")):
        return Severity.HIGH
    if any(k in text for k in ("security group", "policy", "0.0.0.0/0")):
        return Severity.MEDIUM
    if any(k in text for k in ("blocked", "waf", "scan")):
        return Severity.LOW
    return Severity.MEDIUM


def _category_from_alert(alert: SecurityAlert) -> AlertCategory:
    text = f"{alert.title} {alert.description}".lower()
    if "exfiltration" in text or "pii" in text:
        return AlertCategory.DATA_EXFILTRATION
    if "ransomware" in text or "malware" in text or "c2" in text:
        return AlertCategory.MALWARE
    if "rdp" in text or "lateral" in text or "unauthorized" in text:
        return AlertCategory.UNAUTHORIZED_ACCESS
    if "security group" in text or "policy" in text:
        return AlertCategory.POLICY_VIOLATION
    if "waf" in text or "scan" in text:
        return AlertCategory.ANOMALOUS_BEHAVIOR
    return AlertCategory.ANOMALOUS_BEHAVIOR


def offline_classify(alert: SecurityAlert) -> Classification:
    severity = _severity_from_alert(alert)
    category = _category_from_alert(alert)
    return Classification(
        severity=severity,
        category=category,
        confidence=0.85,
        reasoning=f"Offline rule-based classification for {alert.alert_id}",
    )


def offline_investigate(
    alert: SecurityAlert, classification: Classification
) -> Investigation:
    escalate = classification.severity in (Severity.CRITICAL, Severity.HIGH)
    return Investigation(
        findings=[
            f"Scope assessed for {alert.affected_resource}",
            f"Category: {classification.category.value}",
        ],
        affected_scope="production" if escalate else "limited",
        attack_vector="credential compromise" if escalate else "policy misconfiguration",
        ioc_matches=alert.raw_indicators[:3],
        requires_escalation=escalate,
        escalation_reason="Active breach indicators present" if escalate else "",
    )


def offline_remediate(
    alert: SecurityAlert,
    classification: Classification,
    investigation: Investigation,
) -> Remediation:
    disruptive = classification.severity in (Severity.CRITICAL, Severity.HIGH)
    return Remediation(
        immediate_actions=[
            "Isolate affected host from network",
            "Preserve forensic artifacts",
            "Block identified IOCs",
        ],
        long_term_fixes=[
            "Harden IAM policies",
            "Enable enhanced monitoring",
        ],
        playbook_reference=classification.category.value,
        estimated_impact="Service disruption possible" if disruptive else "Minimal impact",
        requires_human_approval=disruptive,
        approval_reason="Disruptive remediation on production workload" if disruptive else "",
    )
