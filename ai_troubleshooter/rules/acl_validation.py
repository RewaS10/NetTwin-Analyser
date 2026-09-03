"""
acl_validation.py
------------------
ACL Validation category. Four independently-testable checks, each with
its own stable rule ID (kept in one module because they all read from
the same ACL-related evidence produced by evidence_analyzer.py):

RULE_18  ACL Missing ICMP/Return-Traffic Permit
    An extended ACL permits only specific, narrow traffic (e.g. a single
    TCP port) and has no rule covering ICMP, while the case evidence
    shows an actual failed ping. Since Cisco ACLs deny anything not
    explicitly permitted, a failed ping plus the absence of any ICMP (or
    blanket 'permit ip any any') rule is direct, deterministic evidence
    that this ACL is the reason ICMP is being dropped. Covers CASE_022.

RULE_19  ACL Wildcard Mask Scope Mismatch
    A permit line expresses its source as `<network> <wildcard>`. If the
    wildcard mask converts to a different prefix length than an
    explicitly stated intended/target subnet that shares the same base
    network address, the ACL is demonstrably granting access to a
    broader (or narrower) range than intended. Covers CASE_023.

RULE_20  ACL Interface/Direction Application Error
    `show ip interface <if>` directly reports which ACL (if any) is
    bound inbound on that interface. If the symptom text names the
    exact interface the affected hosts connect through and describes a
    total loss of connectivity through it, and that same interface has
    an ACL bound inbound, that is direct evidence the ACL is filtering
    all LAN-originated traffic on the wrong interface. Covers CASE_024.

RULE_21  ACL Rule Order Shadowing
    Cisco ACLs are evaluated top-down, first match wins. If a
    catch-all `deny ip any any` line appears at a lower sequence number
    than a `permit` line in the same ACL, that permit line can
    structurally never be reached -- this is provable directly from the
    ACL's own sequence numbers, with no other evidence required. Covers
    CASE_025.

None of these checks infer an ACL problem from a bare connectivity
complaint alone -- each requires the specific piece of ACL evidence
named above.
"""

from __future__ import annotations

import ipaddress
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_troubleshooter.models import (
    NetworkCase,
    ParsedEvidence,
    RuleFinding,
    RuleStatus
)  # noqa: E402
from ai_troubleshooter.rules.base import same_interface # noqa: E402

CATEGORY = "ACL"

_PING_FAILURE_INDICATORS = (
    "request timed out",
    "100% loss",
    "unreachable",
    "cannot receive ping",
)


def _has_ping_failure_evidence(case: NetworkCase) -> bool:
    text = f"{case.symptom} {case.show_outputs}".lower()
    if "ping" not in text and "icmp" not in text:
        return False
    return any(indicator in text for indicator in _PING_FAILURE_INDICATORS)


# ---------------------------------------------------------------------------
# RULE_18 - ACL Missing ICMP/Return-Traffic Permit
# ---------------------------------------------------------------------------


def check_missing_icmp_permit(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_18", "ACL Missing ICMP/Return-Traffic Permit"
    findings: list[RuleFinding] = []

    if not evidence.extended_acl_entries:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No extended ACL evidence ('show access-lists') is "
                "available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show access-lists",
            )
        )
        return findings

    ping_failure = _has_ping_failure_evidence(case)

    for acl in evidence.extended_acl_entries:
        has_icmp_coverage = any(
            line.action == "permit"
            and (line.protocol == "icmp" or (line.protocol == "ip" and line.rest == "any any"))
            for line in acl.lines
        )

        if has_icmp_coverage:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.PASS,
                    finding=f"ACL {acl.acl_name} includes a permit rule covering "
                    "ICMP traffic.",
                    evidence=[acl.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
            continue

        if not ping_failure:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"ACL {acl.acl_name} has no explicit rule permitting "
                    "ICMP, but no failed-ping/ICMP evidence is present for this "
                    "case to confirm that gap is actually causing a problem.",
                    evidence=[acl.source_block],
                    severity=None,
                    recommended_next_command="ping <destination>",
                )
            )
            continue

        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.FAILED,
                finding=f"ACL {acl.acl_name} permits only specific traffic and has "
                "no rule permitting ICMP, while the evidence shows a failed ping "
                "-- consistent with ICMP being dropped by this ACL's implicit or "
                "explicit deny.",
                evidence=[acl.source_block, f"symptom: {case.symptom}"],
                severity=case.severity or "Medium",
                recommended_next_command=None,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RULE_19 - ACL Wildcard Mask Scope Mismatch
# ---------------------------------------------------------------------------


def check_wildcard_mask_scope_mismatch(
    case: NetworkCase, evidence: ParsedEvidence
) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_19", "ACL Wildcard Mask Scope Mismatch"
    findings: list[RuleFinding] = []

    if not evidence.extended_acl_entries:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No extended ACL evidence ('show access-lists') is "
                "available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show access-lists",
            )
        )
        return findings

    if not evidence.stated_lan_subnets:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="Extended ACL evidence is available, but no intended/"
                "target subnet is explicitly stated in the symptom/topology "
                "text to compare its wildcard-mask scope against.",
                evidence=[acl.source_block for acl in evidence.extended_acl_entries],
                severity=None,
                recommended_next_command=None,
            )
        )
        return findings

    matched_any = False
    for acl in evidence.extended_acl_entries:
        for line in acl.lines:
            if line.action != "permit" or not line.source_network:
                continue
            try:
                acl_net = ipaddress.IPv4Network(line.source_network, strict=False)
            except ValueError:
                continue

            for stated in evidence.stated_lan_subnets:
                try:
                    stated_net = ipaddress.IPv4Network(stated.network, strict=False)
                except ValueError:
                    continue
                if acl_net.network_address != stated_net.network_address:
                    continue

                matched_any = True
                if acl_net.prefixlen == stated_net.prefixlen:
                    findings.append(
                        RuleFinding(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            category=CATEGORY,
                            status=RuleStatus.PASS,
                            finding=f"ACL {acl.acl_name} line {line.sequence} "
                            f"permits {line.source_network}, exactly matching the "
                            f"intended target subnet {stated.network}.",
                            evidence=[line.source_line, stated.source_line],
                            severity=None,
                            recommended_next_command=None,
                        )
                    )
                elif acl_net.prefixlen < stated_net.prefixlen:
                    findings.append(
                        RuleFinding(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            category=CATEGORY,
                            status=RuleStatus.FAILED,
                            finding=f"ACL {acl.acl_name} line {line.sequence} uses "
                            f"a wildcard mask that grants access to "
                            f"{line.source_network}, far broader than the "
                            f"intended target subnet {stated.network} -- "
                            "consistent with a wildcard-mask calculation error.",
                            evidence=[line.source_line, stated.source_line],
                            severity=case.severity or "High",
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
                            finding=f"ACL {acl.acl_name} line {line.sequence} "
                            f"permits {line.source_network}, which is narrower "
                            f"than the intended target subnet {stated.network}; "
                            "no over-permissive wildcard detected.",
                            evidence=[line.source_line, stated.source_line],
                            severity=None,
                            recommended_next_command=None,
                        )
                    )

    if not matched_any:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="Extended ACL and intended-subnet evidence are both "
                "present, but no ACL permit line's network shares a base "
                "address with the stated subnet, so wildcard scope cannot be "
                "compared.",
                evidence=[],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RULE_20 - ACL Interface/Direction Application Error
# ---------------------------------------------------------------------------

_CONNECTED_TO_IFACE_RE = re.compile(
    r"connected to\s+([A-Za-z]+\s?\d+(?:/\d+)*)", re.IGNORECASE
)
_TOTAL_BLOCK_INDICATORS = (
    "completely blocked",
    "totally blocked",
    "entirely blocked",
)


def _extract_symptom_interface(symptom: str) -> str | None:
    m = _CONNECTED_TO_IFACE_RE.search(symptom)
    if not m:
        return None
    return m.group(1).replace(" ", "")


def check_interface_direction(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_20", "ACL Interface/Direction Application Error"
    findings: list[RuleFinding] = []

    if not evidence.acl_interface_bindings:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'show ip interface' ACL-binding evidence "
                "(Inbound/Outbound access list) is available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show ip interface <interface>",
            )
        )
        return findings

    symptom_iface = _extract_symptom_interface(case.symptom)
    total_block = any(ind in case.symptom.lower() for ind in _TOTAL_BLOCK_INDICATORS)

    matched_any = False
    for binding in evidence.acl_interface_bindings:
        if not symptom_iface or not same_interface(symptom_iface, binding.interface):
            continue
        matched_any = True

        if binding.inbound_acl and total_block:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"ACL {binding.inbound_acl} is applied inbound on "
                    f"{binding.interface}, the exact interface the symptom "
                    "identifies as where the affected hosts connect, and the "
                    "symptom describes a complete loss of connectivity through "
                    "it -- consistent with the ACL being applied to the wrong "
                    "interface/direction instead of the intended one.",
                    evidence=[binding.source_block, f"symptom: {case.symptom}"],
                    severity=case.severity or "High",
                    recommended_next_command=None,
                )
            )
        elif binding.inbound_acl and not total_block:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"ACL {binding.inbound_acl} is applied inbound on "
                    f"{binding.interface} (matching the symptom's named "
                    "interface), but the symptom does not describe a complete "
                    "loss of connectivity, so a misapplication cannot be "
                    "confirmed from this evidence alone.",
                    evidence=[binding.source_block],
                    severity=None,
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
                    finding=f"{binding.interface} (matching the symptom's named "
                    "interface) has no inbound ACL applied, so ACL "
                    "misapplication on this interface is not evident.",
                    evidence=[binding.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )

    if not matched_any:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="ACL interface-binding evidence is available, but the "
                "symptom text does not name an interface matching any bound "
                "interface, so a misapplication cannot be confirmed.",
                evidence=[b.source_block for b in evidence.acl_interface_bindings],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# RULE_21 - ACL Rule Order Shadowing
# ---------------------------------------------------------------------------


def check_rule_order_shadowing(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_21", "ACL Rule Order Shadowing"
    findings: list[RuleFinding] = []

    if not evidence.extended_acl_entries:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No extended ACL evidence ('show access-lists') is "
                "available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show access-lists",
            )
        )
        return findings

    for acl in evidence.extended_acl_entries:
        broad_denies = [
            line
            for line in acl.lines
            if line.action == "deny" and line.protocol == "ip" and line.rest == "any any"
            and line.sequence is not None
        ]

        if not broad_denies:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.PASS,
                    finding=f"ACL {acl.acl_name} has no catch-all 'deny ip any "
                    "any' line, so rule ordering is not implicated.",
                    evidence=[acl.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
            continue

        shadowed_any = False
        for deny in broad_denies:
            later_permits = [
                line
                for line in acl.lines
                if line.action == "permit"
                and line.sequence is not None
                and line.sequence > deny.sequence
            ]
            for permit in later_permits:
                shadowed_any = True
                findings.append(
                    RuleFinding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        category=CATEGORY,
                        status=RuleStatus.FAILED,
                        finding=f"ACL {acl.acl_name} line {deny.sequence} "
                        "('deny ip any any') precedes permit line "
                        f"{permit.sequence} ('{permit.source_line}'). ACLs are "
                        "evaluated top-down, first match wins, so the permit "
                        "line can never be reached.",
                        evidence=[deny.source_line, permit.source_line],
                        severity=case.severity or "High",
                        recommended_next_command=None,
                    )
                )

        if not shadowed_any:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.PASS,
                    finding=f"ACL {acl.acl_name}'s catch-all 'deny ip any any' "
                    "line appears after all permit lines, so no permit rule is "
                    "shadowed by it.",
                    evidence=[acl.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    """Aggregate entry point so rule_checker.py can treat this as one module."""
    return (
        check_missing_icmp_permit(case, evidence)
        + check_wildcard_mask_scope_mismatch(case, evidence)
        + check_interface_direction(case, evidence)
        + check_rule_order_shadowing(case, evidence)
    )
