"""
nat_validation.py
--------------------
NAT Validation category. Three independently-testable checks, each with
its own stable rule ID (kept in one module because they all read from
the same NAT-related evidence):

RULE_15  NAT Inside/Outside Interface Validation
    `show ip nat statistics` directly reports its Outside/Inside
    interface lists. If the Inside list is empty (literal "none
    configured") while at least one Outside interface is configured,
    that is deterministic evidence NAT cannot function -- packets have
    nothing to translate from. Covers CASE_026.

RULE_16  NAT Overload ACL Subnet Mismatch
    An `ip nat inside source list <acl> ...` rule references a standard
    ACL. If that ACL's permitted network does not match the LAN subnet
    stated in the symptom/topology text, translation will never trigger
    for the real LAN hosts. Covers CASE_027.

RULE_17  NAT Pool Missing Overload
    A `ip nat inside source list <acl> pool <name>` rule has no
    `overload` keyword, and the referenced pool (`show ip nat pool`)
    has exactly one usable address (start == end, or total_addresses ==
    1). Without `overload`, a one-address dynamic pool can serve only
    one simultaneous internal host -- everyone else fails once that
    single translation is in use. Covers CASE_028.

None of these checks infer a NAT problem from a bare "can't reach the
internet" symptom alone -- each requires the specific piece of evidence
named above.
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

CATEGORY = "NAT"


# ---------------------------------------------------------------------------
# RULE_15 - NAT Inside/Outside Interface Validation
# ---------------------------------------------------------------------------


def check_inside_outside_interfaces(
    case: NetworkCase, evidence: ParsedEvidence
) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_15", "NAT Inside/Outside Interface Validation"
    findings: list[RuleFinding] = []

    if not evidence.nat_statistics:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'show ip nat statistics' output is available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show ip nat statistics",
            )
        )
        return findings

    for stats in evidence.nat_statistics:
        who = stats.device or "the router"
        has_outside = bool(stats.outside_interfaces)
        has_inside = bool(stats.inside_interfaces)

        if has_outside and not has_inside:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who} has an outside NAT interface configured "
                    f"({stats.outside_interfaces}) but no inside NAT interface "
                    "-- NAT has no LAN-side interface to translate from.",
                    evidence=[
                        f"show ip nat statistics: Outside interfaces = {stats.outside_interfaces}",
                        "show ip nat statistics: Inside interfaces = none configured"
                        if stats.inside_none_configured
                        else "show ip nat statistics: Inside interfaces = (empty)",
                    ],
                    severity="Critical",
                    recommended_next_command=None,
                )
            )
        elif not has_outside and has_inside:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who} has an inside NAT interface configured "
                    f"({stats.inside_interfaces}) but no outside NAT interface "
                    "-- NAT has no WAN-side interface to translate to.",
                    evidence=[
                        f"show ip nat statistics: Inside interfaces = {stats.inside_interfaces}",
                        "show ip nat statistics: Outside interfaces = none configured"
                        if stats.outside_none_configured
                        else "show ip nat statistics: Outside interfaces = (empty)",
                    ],
                    severity="Critical",
                    recommended_next_command=None,
                )
            )
        elif not has_outside and not has_inside:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who} has neither an inside nor an outside NAT "
                    "interface configured.",
                    evidence=[stats.source_block],
                    severity="Critical",
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
                    finding=f"{who} has both an inside NAT interface "
                    f"({stats.inside_interfaces}) and an outside NAT interface "
                    f"({stats.outside_interfaces}) configured.",
                    evidence=[stats.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RULE_16 - NAT Overload ACL Subnet Mismatch
# ---------------------------------------------------------------------------


def check_acl_subnet_mismatch(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_16", "NAT Overload ACL Subnet Mismatch"
    findings: list[RuleFinding] = []

    acl_rules = [r for r in evidence.nat_inside_source_rules if r.acl_number]

    if not acl_rules:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'ip nat inside source list <acl> ...' configuration "
                "referencing an ACL is available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show running-config | include nat",
            )
        )
        return findings

    if not evidence.standard_acl_entries:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A NAT rule references an ACL, but that ACL's contents "
                "('show access-lists') are not available in the evidence.",
                evidence=[r.source_line for r in acl_rules],
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
                finding="The referenced ACL's permitted network is known, but no "
                "actual LAN subnet is stated in the symptom/topology text to "
                "compare it against.",
                evidence=[a.source_block for a in evidence.standard_acl_entries],
                severity=None,
                recommended_next_command=None,
            )
        )
        return findings

    for rule in acl_rules:
        acl = next(
            (a for a in evidence.standard_acl_entries if a.acl_number == rule.acl_number), None
        )
        if acl is None or acl.permitted_network is None:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"NAT rule references ACL {rule.acl_number}, but its "
                    "permitted network could not be determined from the evidence.",
                    evidence=[rule.source_line],
                    severity=None,
                    recommended_next_command="show access-lists",
                )
            )
            continue

        for lan in evidence.stated_lan_subnets:
            if acl.permitted_network != lan.network:
                findings.append(
                    RuleFinding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        category=CATEGORY,
                        status=RuleStatus.FAILED,
                        finding=f"NAT overload rule uses ACL {rule.acl_number}, which "
                        f"permits {acl.permitted_network}, but the active LAN hosts "
                        f"are in {lan.network} -- NAT will never match their traffic.",
                        evidence=[
                            f"running-config: {rule.source_line}",
                            f"show access-lists {rule.acl_number}: permits {acl.permitted_network}",
                            f"stated LAN subnet: {lan.source_line}",
                        ],
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
                        finding=f"NAT overload rule's ACL {rule.acl_number} permits "
                        f"{acl.permitted_network}, matching the stated LAN subnet "
                        f"{lan.network}.",
                        evidence=[rule.source_line, acl.source_block],
                        severity=None,
                        recommended_next_command=None,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# RULE_17 - NAT Pool Missing Overload
# ---------------------------------------------------------------------------


def check_pool_missing_overload(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_17", "NAT Pool Missing Overload"
    findings: list[RuleFinding] = []

    pool_rules = [r for r in evidence.nat_inside_source_rules if r.pool_name]

    if not pool_rules:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'ip nat inside source list <acl> pool <name>' "
                "configuration is available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show running-config | include ip nat inside source",
            )
        )
        return findings

    if not evidence.nat_pools:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A NAT rule references a pool, but that pool's details "
                "('show ip nat pool') are not available in the evidence.",
                evidence=[r.source_line for r in pool_rules],
                severity=None,
                recommended_next_command="show ip nat pool",
            )
        )
        return findings

    for rule in pool_rules:
        pool = next((p for p in evidence.nat_pools if p.pool_name == rule.pool_name), None)
        if pool is None:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"NAT rule references pool {rule.pool_name}, but its "
                    "details were not found in the evidence.",
                    evidence=[rule.source_line],
                    severity=None,
                    recommended_next_command="show ip nat pool",
                )
            )
            continue

        is_single_address = (
            pool.total_addresses == 1
            or (pool.start_ip is not None and pool.start_ip == pool.end_ip)
        )

        if is_single_address is False and pool.total_addresses is None and pool.start_ip is None:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"Pool {pool.pool_name}'s address range/count was not "
                    "found, so single-address exhaustion cannot be confirmed.",
                    evidence=[pool.source_block],
                    severity=None,
                    recommended_next_command="show ip nat pool",
                )
            )
            continue

        if is_single_address and not rule.overload:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"NAT rule uses pool {pool.pool_name}, which has only "
                    "one usable public address, but the rule is missing the "
                    "'overload' keyword -- only one internal host can be "
                    "translated at a time.",
                    evidence=[
                        f"running-config: {rule.source_line}",
                        f"show ip nat pool {pool.pool_name}: "
                        f"start {pool.start_ip} end {pool.end_ip}"
                        + (
                            f", total addresses {pool.total_addresses}"
                            if pool.total_addresses is not None
                            else ""
                        ),
                    ],
                    severity="High",
                    recommended_next_command=None,
                )
            )
        elif is_single_address and rule.overload:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.PASS,
                    finding=f"NAT rule uses pool {pool.pool_name} (single address) "
                    "with the 'overload' keyword, correctly enabling PAT for "
                    "multiple internal hosts.",
                    evidence=[rule.source_line, pool.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
        else:
            # Multi-address pool -- overload isn't required for basic operation.
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.PASS,
                    finding=f"Pool {pool.pool_name} has more than one usable "
                    "address, so a missing 'overload' keyword does not by itself "
                    "cause single-host exhaustion.",
                    evidence=[pool.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    """Aggregate entry point so rule_checker.py can treat this as one module."""
    return (
        check_inside_outside_interfaces(case, evidence)
        + check_acl_subnet_mismatch(case, evidence)
        + check_pool_missing_overload(case, evidence)
    )
