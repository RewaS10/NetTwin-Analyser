"""
vlan_validation.py
--------------------
VLAN Validation category. Three separate, independently-testable checks,
each with its own stable rule ID (kept in one module because they all
read from the same VLAN-related evidence):

RULE_05  Missing VLAN
    A `switchport access vlan N` line exists in a running-config excerpt,
    but VLAN N does not appear in the switch's `show vlan brief` table.
    Covers CASE_005.

RULE_06  VLAN Assignment Mismatch
    topology_note states an intended VLAN for a port (e.g. "Fa0/1
    (intended VLAN 20)"), but `show vlan brief` shows that port is
    actually a member of a different VLAN. Covers CASE_001.

RULE_07  Native VLAN Mismatch
    Two `show interfaces <if> switchport` blocks from different devices
    report different Administrative Native VLAN values for what the case
    describes as the same trunk link. Covers CASE_002.

NOTE ON SCOPE: trunk *allowed-VLAN* problems (CASE_003) and trunk
*mode* mismatches such as one side access / other side trunk (CASE_004)
are handled by the separate Trunk Validation category (category #6 in
the project spec), not here -- even though the dataset's concept_tag for
those cases is "VLAN". They are intentionally deferred to the next
implementation batch (see IMPLEMENTATION_PLAN.md).
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

CATEGORY = "VLAN"


# ---------------------------------------------------------------------------
# RULE_05 - Missing VLAN
# ---------------------------------------------------------------------------


def check_missing_vlan(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_05", "Missing VLAN"
    findings: list[RuleFinding] = []

    if not evidence.running_config_vlan_assignments:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'switchport access vlan' configuration was found in this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show running-config",
            )
        )
        return findings

    if not evidence.vlan_entries:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A port's access VLAN assignment was found, but no "
                "'show vlan brief' output is available to confirm whether that "
                "VLAN exists on the switch.",
                evidence=[a.source_line for a in evidence.running_config_vlan_assignments],
                severity=None,
                recommended_next_command="show vlan brief",
            )
        )
        return findings

    known_vlans = {v.vlan_id for v in evidence.vlan_entries}
    for assignment in evidence.running_config_vlan_assignments:
        if assignment.vlan_id not in known_vlans:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"VLAN {assignment.vlan_id} is assigned to port "
                    f"{assignment.interface or 'an interface'} but does not exist "
                    "in the switch's VLAN database.",
                    evidence=[
                        f"Running-config: {assignment.source_line} "
                        f"(interface {assignment.interface})",
                        f"show vlan brief does not list VLAN {assignment.vlan_id} "
                        f"(known VLANs: {sorted(known_vlans)})",
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
                    finding=f"VLAN {assignment.vlan_id} assigned to port "
                    f"{assignment.interface or 'an interface'} exists in the VLAN database.",
                    evidence=[f"show vlan brief lists VLAN {assignment.vlan_id}"],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RULE_06 - VLAN Assignment Mismatch
# ---------------------------------------------------------------------------


def check_vlan_assignment_mismatch(
    case: NetworkCase, evidence: ParsedEvidence
) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_06", "VLAN Assignment Mismatch"
    findings: list[RuleFinding] = []

    if not evidence.intended_vlan_bindings:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No statement of an intended VLAN for a specific port was "
                "found in the topology notes for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show vlan brief",
            )
        )
        return findings

    if not evidence.vlan_entries:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="An intended VLAN binding was found, but no 'show vlan "
                "brief' output is available to confirm the port's actual VLAN.",
                evidence=[b.source_line for b in evidence.intended_vlan_bindings],
                severity=None,
                recommended_next_command="show vlan brief",
            )
        )
        return findings

    for binding in evidence.intended_vlan_bindings:
        actual_vlan = None
        for entry in evidence.vlan_entries:
            if binding.port in entry.ports:
                actual_vlan = entry.vlan_id
                break

        if actual_vlan is None:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"Port {binding.port} was not found in any VLAN entry "
                    "of the show vlan brief output, so its actual VLAN is unknown.",
                    evidence=[binding.source_line]
                    + [f"VLAN {v.vlan_id} ports: {v.ports}" for v in evidence.vlan_entries],
                    severity=None,
                    recommended_next_command="show vlan brief",
                )
            )
        elif actual_vlan != binding.intended_vlan:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"Port {binding.port} is intended for VLAN "
                    f"{binding.intended_vlan} but is actually assigned to VLAN {actual_vlan}.",
                    evidence=[
                        f"topology_note: {binding.source_line}",
                        f"show vlan brief: VLAN {actual_vlan} ports include {binding.port}",
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
                    finding=f"Port {binding.port} is correctly assigned to its "
                    f"intended VLAN {binding.intended_vlan}.",
                    evidence=[f"show vlan brief: VLAN {actual_vlan} ports include {binding.port}"],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RULE_07 - Native VLAN Mismatch
# ---------------------------------------------------------------------------


def check_native_vlan_mismatch(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_07", "Native VLAN Mismatch"
    findings: list[RuleFinding] = []

    # Note: not every switchport block in this dataset repeats "Administrative
    # Mode: trunk" (some CLI captures only print the native-VLAN lines once
    # trunk mode has already been established elsewhere in the same block).
    # We treat the presence of an Administrative Native VLAN value itself as
    # sufficient evidence that this port is being reported in a trunk context.
    trunk_ports = [
        sp for sp in evidence.switchport_infos if sp.administrative_native_vlan is not None
    ]

    if len(trunk_ports) < 2:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="Fewer than two trunk-side 'show interfaces switchport' "
                "outputs with a native VLAN are available, so a native VLAN "
                "mismatch across a trunk link cannot be confirmed.",
                evidence=[sp.source_block for sp in trunk_ports],
                severity=None,
                recommended_next_command="show interfaces switchport",
            )
        )
        return findings

    native_vlans = {sp.administrative_native_vlan for sp in trunk_ports}
    if len(native_vlans) > 1:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.FAILED,
                finding="Native VLAN mismatch detected across a trunk link: "
                + ", ".join(
                    f"{sp.device or 'device'} reports native VLAN "
                    f"{sp.administrative_native_vlan}"
                    for sp in trunk_ports
                )
                + ".",
                evidence=[sp.source_block for sp in trunk_ports],
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
                finding=f"Both ends of the trunk link agree on native VLAN "
                f"{native_vlans.pop()}.",
                evidence=[sp.source_block for sp in trunk_ports],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    """Aggregate entry point so rule_checker.py can treat this as one module."""
    return (
        check_missing_vlan(case, evidence)
        + check_vlan_assignment_mismatch(case, evidence)
        + check_native_vlan_mismatch(case, evidence)
    )
