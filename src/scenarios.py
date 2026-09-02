"""Sample security alert scenarios for demo and testing."""

from __future__ import annotations

from .models import SecurityAlert

SAMPLE_ALERTS: list[SecurityAlert] = [
    SecurityAlert(
        alert_id="ALT-2026-0847",
        source="AWS GuardDuty",
        title="Unusual API calls from IAM user in production account",
        description=(
            "IAM user 'svc-data-pipeline' made 847 ListBuckets and GetObject calls "
            "to S3 buckets containing PII data from an IP address in a country where "
            "the organization has no operations. Activity occurred between 02:00-04:00 UTC, "
            "outside normal business hours."
        ),
        raw_indicators=["IP: 185.220.101.34", "Tor exit node", "847 API calls in 2 hours"],
        affected_resource="arn:aws:s3:::prod-customer-pii-data",
        timestamp="2026-05-23T03:15:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0848",
        source="AWS Config",
        title="Security group modified to allow 0.0.0.0/0 on port 22",
        description=(
            "Production security group sg-0a1b2c3d was modified to allow inbound SSH "
            "from any IP address. Change was made by IAM user 'dev-john' outside of "
            "the approved change window."
        ),
        raw_indicators=["sg-0a1b2c3d", "0.0.0.0/0:22", "outside change window"],
        affected_resource="arn:aws:ec2:us-west-2:123456789:security-group/sg-0a1b2c3d",
        timestamp="2026-05-23T14:22:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0849",
        source="AWS WAF",
        title="SQL injection attempts blocked - elevated volume",
        description=(
            "WAF rule 'SQLi-Detection' blocked 1,247 requests from distributed IPs "
            "targeting /api/v2/accounts endpoint. Pattern suggests automated scanning "
            "tool. All requests blocked, no successful exploitation detected."
        ),
        raw_indicators=["1247 blocked requests", "distributed IPs", "/api/v2/accounts"],
        affected_resource="arn:aws:elasticloadbalancing:us-east-1:123456789:app/prod-api",
        timestamp="2026-05-23T11:45:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0850",
        source="CrowdStrike EDR",
        title="Ransomware behavior detected on endpoint",
        description=(
            "Endpoint WIN-PROD-042 exhibited ransomware indicators: mass file encryption "
            "with .locked extension, shadow copy deletion, and outbound C2 beaconing to "
            "185.234.219.12 on port 443. Process: svchost.exe (PID 4892) spawned from "
            "suspicious PowerShell download cradle."
        ),
        raw_indicators=[
            "C2: 185.234.219.12:443",
            "MITRE T1486",
            "MITRE T1071.001",
            "ransomware extension .locked",
        ],
        affected_resource="WIN-PROD-042",
        timestamp="2026-05-23T08:30:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0851",
        source="Microsoft Defender for Identity",
        title="Lateral movement via RDP from compromised workstation",
        description=(
            "User account 'jsmith' authenticated via RDP to 12 internal servers within "
            "15 minutes from workstation WS-FIN-019. Source IP matches prior brute-force "
            "alert. Unusual admin share access (C$, ADMIN$) detected on file servers."
        ),
        raw_indicators=[
            "RDP to 12 hosts in 15 min",
            "MITRE T1021.001",
            "admin share enumeration",
            "prior brute-force on jsmith",
        ],
        affected_resource="WS-FIN-019",
        timestamp="2026-05-23T09:45:00Z",
    ),
    SecurityAlert(
        alert_id="ALT-2026-0852",
        source="Palo Alto IDS",
        title="External vulnerability scan detected - all attempts blocked",
        description=(
            "IDS detected 342 probe requests from 89 external IPs targeting common "
            "vulnerability paths (/admin, /phpMyAdmin, /.env). All requests blocked "
            "by perimeter firewall. No successful exploitation or internal lateral "
            "movement observed. Pattern consistent with internet-wide scanning."
        ),
        raw_indicators=[
            "342 blocked probes",
            "89 source IPs",
            "vulnerability scan pattern",
            "no exploitation",
        ],
        affected_resource="perimeter-fw-prod-01",
        timestamp="2026-05-23T16:00:00Z",
    ),
]

SCENARIO_EXPECTATIONS = {
    "ALT-2026-0847": {"gate1": True, "gate2": True},
    "ALT-2026-0848": {"gate1": False, "gate2": False},
    "ALT-2026-0849": {"gate1": False, "gate2": False},
    "ALT-2026-0850": {"gate1": True, "gate2": True},
    "ALT-2026-0851": {"gate1": True, "gate2": True},
    "ALT-2026-0852": {"gate1": False, "gate2": False},
}
