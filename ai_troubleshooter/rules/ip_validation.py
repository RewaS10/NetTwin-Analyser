"""
ip_validation.py
-----------------
RULE_01: IP Address Validation

Checks every IP address the evidence analyzer found (host IPs, gateway
IPs, router interface IPs) for basic well-formedness.

Deterministic scope (see DATASET_ASSESSMENT.md):
The current dataset does not contain any deliberately malformed IP
addresses -- every case's evidence uses syntactically valid IPv4
addresses. This rule therefore PASSes on all 30 real cases today. It is
kept in the engine because (a) later Gateway/Subnet rules depend on the
IPs being well-formed first, and (b) future dataset additions may include
malformed-IP cases. See tests/test_rules.py for a synthetic malformed-IP
test that proves the FAILED path works.

Duplicate-IP-address detection is NOT implemented: it would require two
hosts on the same broadcast domain both reporting an IP, and no case in
the current dataset provides that evidence.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_troubleshooter.models import (
    NetworkCase,
    ParsedEvidence,
    RuleFinding,
    RuleStatus
)  # noqa: E402
from ai_troubleshooter.rules.base import (
    is_valid_ipv4
) # noqa: E402

RULE_ID = "RULE_01"
RULE_NAME = "IP Address Validation"
CATEGORY = "IP"


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    findings: list[RuleFinding] = []

    # Gather every IP address the analyzer found, tagged with where it came from.
    candidates: list[tuple[str, str]] = []  # (ip, description)
    for cfg in evidence.ip_configs:
        if cfg.ip_address:
            who = cfg.device or cfg.interface or "host"
            candidates.append((cfg.ip_address, f"IP address of {who}"))
        if cfg.default_gateway:
            who = cfg.device or "host"
            candidates.append((cfg.default_gateway, f"default gateway configured on {who}"))
    for entry in evidence.interface_briefs:
        if entry.ip_address.lower() != "unassigned":
            candidates.append((entry.ip_address, f"IP address of interface {entry.interface}"))

    if not candidates:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No IP address evidence (ipconfig, show ip interface, "
                "or show ip interface brief) was found in this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show ip interface brief",
            )
        )
        return findings

    bad = [(ip, desc) for ip, desc in candidates if not is_valid_ipv4(ip)]
    if bad:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.FAILED,
                finding=f"{len(bad)} malformed IPv4 address(es) found in the supplied evidence.",
                evidence=[f"'{ip}' ({desc}) is not a valid IPv4 address." for ip, desc in bad],
                severity="High",
                recommended_next_command=None,
            )
        )
    else:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.PASS,
                finding=f"All {len(candidates)} IP address(es) found in the evidence are well-formed.",
                evidence=[f"'{ip}' ({desc}) is a valid IPv4 address." for ip, desc in candidates],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings
