"""Individual agent implementations for the triage pipeline."""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage

from .guardrails import check_alert_input, validate_remediation_actions
from .knowledge_base import get_playbook, search_playbooks
from .llm import get_langfuse_callbacks, get_llm, is_offline_mode, structured_output
from .models import (
    Classification,
    Investigation,
    Remediation,
    SecurityAlert,
)
from .offline import offline_classify, offline_investigate, offline_remediate

CLASSIFIER_PROMPT = """You are a security alert classifier working in a SOC.
Given a raw security alert, classify it by severity and category.

Severity levels:
- critical: Active breach, data loss imminent, requires immediate response
- high: Confirmed malicious activity, significant risk if not addressed within 1 hour
- medium: Suspicious activity requiring investigation within 4 hours
- low: Minor policy violation or informational alert
- info: Noise, false positive, or expected behavior

Categories:
- unauthorized_access: Failed/successful auth from unusual source
- data_exfiltration: Unusual data transfer patterns
- malware: Known malicious signatures or C2 communication
- policy_violation: Security policy or compliance breach
- anomalous_behavior: Statistical deviation from baseline
- configuration_drift: Infrastructure config changed unexpectedly

Respond with JSON containing: severity, category, confidence (0-1), reasoning."""


INVESTIGATOR_PROMPT = """You are a security investigator. Given a classified alert,
conduct a deeper investigation to determine scope, attack vector, and whether
escalation is needed.

Consider:
1. What is the blast radius?
2. Is this part of a larger attack chain?
3. Are there indicators of compromise (IOCs) that need cross-referencing?
4. Does this require human escalation? (escalate if: critical severity,
   data loss confirmed, active attacker present, or compliance breach)

Respond with JSON: findings (list), affected_scope, attack_vector,
ioc_matches (list), requires_escalation (bool), escalation_reason."""


REMEDIATION_PROMPT = """You are a security remediation specialist. Given an
investigated alert and relevant playbook context, recommend immediate and
long-term actions.

Rules:
- Immediate actions should be executable within minutes
- Long-term fixes should prevent recurrence
- Flag for human approval if: action could cause service disruption,
  affects production workloads, or involves credential revocation for
  service accounts

Playbook context:
{playbook_context}

Respond with JSON: immediate_actions (list), long_term_fixes (list),
playbook_reference, estimated_impact, requires_human_approval (bool),
approval_reason."""


async def classify_alert(alert: SecurityAlert) -> Classification:
    """Classify a security alert by severity and category."""
    safe, reason = check_alert_input(alert.description)
    if not safe:
        raise ValueError(f"Alert input blocked by guardrails: {reason}")

    if is_offline_mode():
        return offline_classify(alert)

    llm = get_llm()
    structured_llm = structured_output(llm, Classification)
    callbacks = get_langfuse_callbacks()

    result = await structured_llm.ainvoke(
        [
            SystemMessage(content=CLASSIFIER_PROMPT),
            HumanMessage(
                content=f"""Alert ID: {alert.alert_id}
Source: {alert.source}
Title: {alert.title}
Description: {alert.description}
Indicators: {', '.join(alert.raw_indicators)}
Affected Resource: {alert.affected_resource}
Timestamp: {alert.timestamp}"""
            ),
        ],
        config={"callbacks": callbacks} if callbacks else None,
    )
    return result


async def investigate_alert(
    alert: SecurityAlert, classification: Classification
) -> Investigation:
    """Investigate a classified alert for scope and escalation needs."""
    if is_offline_mode():
        return offline_investigate(alert, classification)

    llm = get_llm()
    structured_llm = structured_output(llm, Investigation)
    callbacks = get_langfuse_callbacks()

    result = await structured_llm.ainvoke(
        [
            SystemMessage(content=INVESTIGATOR_PROMPT),
            HumanMessage(
                content=f"""Alert: {alert.title}
Description: {alert.description}
Classification: {classification.severity.value} / {classification.category.value}
Confidence: {classification.confidence}
Indicators: {', '.join(alert.raw_indicators)}
Resource: {alert.affected_resource}"""
            ),
        ],
        config={"callbacks": callbacks} if callbacks else None,
    )
    return result


async def recommend_remediation(
    alert: SecurityAlert,
    classification: Classification,
    investigation: Investigation,
) -> Remediation:
    """Generate remediation recommendations using playbook RAG."""
    playbook = get_playbook(classification.category.value)
    related = search_playbooks(alert.description)

    playbook_context = f"""Primary playbook: {playbook['title']}
Immediate actions reference: {playbook.get('immediate', [])}
Long-term fixes reference: {playbook.get('long_term', [])}
Investigation steps: {playbook.get('investigation', [])}"""

    if playbook.get("phase"):
        playbook_context += (
            f"\nPhase: {playbook['phase']}, Action: {playbook.get('action', '')}, "
            f"Tools: {playbook.get('tools', '')}, Response time: {playbook.get('response_time', '')}"
        )

    if related:
        playbook_context += (
            f"\n\nRelated playbooks: {[r['playbook']['title'] for r in related]}"
        )

    if is_offline_mode():
        return offline_remediate(alert, classification, investigation)

    llm = get_llm()
    structured_llm = structured_output(llm, Remediation)
    callbacks = get_langfuse_callbacks()
    prompt = REMEDIATION_PROMPT.format(playbook_context=playbook_context)

    result = await structured_llm.ainvoke(
        [
            SystemMessage(content=prompt),
            HumanMessage(
                content=f"""Alert: {alert.title}
Severity: {classification.severity.value}
Category: {classification.category.value}
Investigation findings: {investigation.findings}
Scope: {investigation.affected_scope}
Attack vector: {investigation.attack_vector}
Requires escalation: {investigation.requires_escalation}
Resource: {alert.affected_resource}"""
            ),
        ],
        config={"callbacks": callbacks} if callbacks else None,
    )

    valid, reason = validate_remediation_actions(result.immediate_actions)
    if not valid:
        result.requires_human_approval = True
        result.approval_reason = f"Guardrail flagged action: {reason}"

    return result
