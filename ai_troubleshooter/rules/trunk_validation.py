"""
trunk_validation.py
---------------------
Trunk Validation category. Two independently-testable checks, each with
its own stable rule ID:

RULE_08  Trunk Allowed-VLAN Validation
    A `show interfaces trunk` block lists the VLANs allowed across a
    trunk. If the case's symptom/topology text names a VLAN whose hosts
    are having trouble, and that VLAN is missing from the trunk's
    allowed-VLAN list, that is a deterministic finding. Covers CASE_003
    (SW1's trunk allows only 10,20; VLAN 30 traffic is symptomatic and
    is not in that list).

RULE_09  Trunk Mode Mismatch
    Two `show interfaces <if> switchport` blocks from different devices,
    for what the case describes as the same inter-switch link, report
    different administrative modes (e.g. one "trunk", the other "static
    access"). Covers CASE_004.

Scope note: this module does NOT re-implement Native VLAN Mismatch
(RULE_07, already in vlan_validation.py) even though it also reads
switchport blocks -- that stays where it is to avoid duplicating logic
across two modules.
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

CATEGORY = "Trunk"


# ---------------------------------------------------------------------------
# RULE_08 - Trunk Allowed-VLAN Validation
# ---------------------------------------------------------------------------


def check_allowed_vlan(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_08", "Trunk Allowed-VLAN Validation"
    findings: list[RuleFinding] = []

    if not evidence.trunk_infos:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'show interfaces trunk' output is available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show interfaces trunk",
            )
        )
        return findings

    if not evidence.mentioned_vlans:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A trunk's allowed-VLAN list is available, but no specific "
                "VLAN is named in the symptom/topology text to check against it.",
                evidence=[t.source_block for t in evidence.trunk_infos],
                severity=None,
                recommended_next_command=None,
            )
        )
        return findings

    for trunk in evidence.trunk_infos:
        missing = [v for v in evidence.mentioned_vlans if v not in trunk.allowed_vlans]
        who = f"{trunk.device or 'a switch'} trunk port {trunk.port or '(unknown)'}"
        if missing:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who} does not permit VLAN(s) {missing} on the trunk, "
                    "but the symptom describes traffic issues for that VLAN.",
                    evidence=[
                        f"show interfaces trunk: allowed VLANs on {who} = {trunk.allowed_vlans}",
                        f"Symptom/topology mentions VLAN(s): {evidence.mentioned_vlans}",
                    ],
                    severity="Medium",
                    recommended_next_command=None,
                )
            )
        else:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.PASS,
                    finding=f"{who} permits all VLAN(s) named in the symptom/topology text.",
                    evidence=[f"show interfaces trunk: allowed VLANs = {trunk.allowed_vlans}"],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RULE_09 - Trunk Mode Mismatch
# ---------------------------------------------------------------------------


def _is_trunk_mode(mode: str | None) -> bool | None:
    if not mode:
        return None
    return "trunk" in mode.lower()


def check_mode_mismatch(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_09", "Trunk Mode Mismatch"
    findings: list[RuleFinding] = []

    with_mode = [
        sp for sp in evidence.switchport_infos if sp.administrative_mode is not None
    ]

    if len(with_mode) < 2:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="Fewer than two 'show interfaces switchport' outputs with an "
                "administrative mode are available, so a trunk/access mode mismatch "
                "across a link cannot be confirmed.",
                evidence=[sp.source_block for sp in with_mode],
                severity=None,
                recommended_next_command="show interfaces switchport",
            )
        )
        return findings

    modes = {_is_trunk_mode(sp.administrative_mode) for sp in with_mode}
    if len(modes) > 1:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.FAILED,
                finding="Switchport mode mismatch detected across an inter-switch link: "
                + ", ".join(
                    f"{sp.device or 'device'} is {sp.administrative_mode}" for sp in with_mode
                )
                + ".",
                evidence=[sp.source_block for sp in with_mode],
                severity="High",
                recommended_next_command=None,
            )
        )
    else:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.PASS,
                finding="Both ends of the link agree on switchport mode "
                f"({with_mode[0].administrative_mode}).",
                evidence=[sp.source_block for sp in with_mode],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    """Aggregate entry point so rule_checker.py can treat this as one module."""
    return check_allowed_vlan(case, evidence) + check_mode_mismatch(case, evidence)
