"""
interface_status.py
---------------------
RULE_04: Interface Status Validation

Reads rows of a `show ip interface brief` table and flags any interface
that is administratively down or otherwise down/down. Covers CASE_008 in
the real dataset (subinterface Gi0/0.10 "administratively down").

Only interfaces actually present in a parsed `show ip interface brief`
table are checked -- this rule never infers an interface problem from a
ping failure alone.
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
) # noqa: E402

RULE_ID = "RULE_04"
RULE_NAME = "Interface Status Validation"
CATEGORY = "Interface"


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    findings: list[RuleFinding] = []

    if not evidence.interface_briefs:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'show ip interface brief' evidence was found in this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show ip interface brief",
            )
        )
        return findings

    down_entries = [
        e
        for e in evidence.interface_briefs
        if "administratively down" in e.status.lower()
        or e.status.lower() == "down"
        or e.protocol.lower() == "down"
    ]

    if down_entries:
        for e in down_entries:
            findings.append(
                RuleFinding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"Interface {e.interface} is {e.status}/{e.protocol}.",
                    evidence=[f"show ip interface brief row: {e.source_line}"],
                    severity="Critical" if "administratively down" in e.status.lower() else "High",
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
                finding=f"All {len(evidence.interface_briefs)} interface(s) in the "
                "show ip interface brief output are up/up.",
                evidence=[e.source_line for e in evidence.interface_briefs],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings
