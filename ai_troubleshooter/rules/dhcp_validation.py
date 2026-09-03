"""
dhcp_validation.py
---------------------
DHCP Validation category. Four independently-testable checks, each with
its own stable rule ID:

RULE_11  DHCP Pool Exhaustion
    `show ip dhcp pool <name>` reports leased addresses >= total
    addresses in the pool. Covers CASE_010.

RULE_12  DHCP Relay / Helper-Address Validation
    topology_note states a centralized DHCP server IP that is outside a
    router subinterface's own subnet, but that subinterface's
    running-config has no `ip helper-address` line pointing at it. Covers
    CASE_011.

RULE_13  DHCP Excluded-Address / Binding Conflict
    A DHCP pool's `default-router` IP appears as a leased client address
    in `show ip dhcp binding` -- direct evidence the gateway IP was never
    excluded from the pool and got handed out to a host. Covers CASE_012.

RULE_14  DHCP Global Service Validation
    `no service dhcp` is present in the evidence, meaning the DHCP
    service itself is administratively disabled router-wide. Covers
    CASE_013.

All four checks follow the same evidence-first principle as the rest of
the engine: a rule only reports FAILED when its specific required
evidence directly demonstrates the fault. Absence of that evidence is
always INSUFFICIENT_EVIDENCE with a recommended next command, never a
guessed FAILED.
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
    host_network,
    ip_in_network
)  # noqa: E402

CATEGORY = "DHCP"


# ---------------------------------------------------------------------------
# RULE_11 - DHCP Pool Exhaustion
# ---------------------------------------------------------------------------


def check_pool_exhaustion(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_11", "DHCP Pool Exhaustion"
    findings: list[RuleFinding] = []

    if not evidence.dhcp_pool_stats:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'show ip dhcp pool <name>' utilization output is available.",
                evidence=[],
                severity=None,
                recommended_next_command="show ip dhcp pool",
            )
        )
        return findings

    for pool in evidence.dhcp_pool_stats:
        who = f"pool {pool.pool_name or '(unknown)'} on {pool.device or 'the DHCP server'}"
        if pool.total_addresses is None or pool.leased_addresses is None:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"{who} is missing total/leased address counts.",
                    evidence=[pool.source_block],
                    severity=None,
                    recommended_next_command="show ip dhcp pool",
                )
            )
        elif pool.leased_addresses >= pool.total_addresses > 0:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who} is exhausted: {pool.leased_addresses} of "
                    f"{pool.total_addresses} addresses leased.",
                    evidence=[pool.source_block],
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
                    finding=f"{who} has free capacity: {pool.leased_addresses} of "
                    f"{pool.total_addresses} addresses leased.",
                    evidence=[pool.source_block],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RULE_12 - DHCP Relay / Helper-Address Validation
# ---------------------------------------------------------------------------


def check_relay_helper_address(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_12", "DHCP Relay / Helper-Address Validation"
    findings: list[RuleFinding] = []

    if not evidence.stated_dhcp_servers:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No centralized DHCP server address is stated in the "
                "topology notes, so it cannot be determined whether relay is needed.",
                evidence=[],
                severity=None,
                recommended_next_command="show running-config",
            )
        )
        return findings

    if not evidence.dhcp_interface_configs:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A centralized DHCP server is stated, but no router "
                "interface running-config is available to check for an "
                "ip helper-address line.",
                evidence=[s.source_line for s in evidence.stated_dhcp_servers],
                severity=None,
                recommended_next_command="show running-config interface",
            )
        )
        return findings

    for server in evidence.stated_dhcp_servers:
        for iface in evidence.dhcp_interface_configs:
            who = f"{iface.device or 'router'} interface {iface.interface or '(unknown)'}"

            if not iface.ip_address or not iface.subnet_mask:
                findings.append(
                    RuleFinding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        category=CATEGORY,
                        status=RuleStatus.INSUFFICIENT_EVIDENCE,
                        finding=f"{who}'s own IP/mask were not found, so it cannot "
                        "be confirmed the DHCP server is on a different subnet "
                        "(relay would only be needed in that case).",
                        evidence=[iface.source_block],
                        severity=None,
                        recommended_next_command="show running-config interface",
                    )
                )
                continue

            network = host_network(iface.ip_address, iface.subnet_mask)
            if network is None:
                continue  # malformed IP/mask -- IP/Subnet rules already flag this

            server_in_subnet = ip_in_network(server.ip_address, network)
            if server_in_subnet is None:
                continue  # malformed server IP

            if server_in_subnet:
                # Server is local to this subnet -- no relay is needed here.
                continue

            if iface.helper_addresses:
                if server.ip_address in iface.helper_addresses:
                    findings.append(
                        RuleFinding(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            category=CATEGORY,
                            status=RuleStatus.PASS,
                            finding=f"{who} correctly relays DHCP requests to "
                            f"{server.ip_address} via ip helper-address.",
                            evidence=[iface.source_block],
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
                            status=RuleStatus.FAILED,
                            finding=f"{who} has ip helper-address configured for "
                            f"{iface.helper_addresses}, but not for the stated DHCP "
                            f"server {server.ip_address}.",
                            evidence=[
                                iface.source_block,
                                f"topology_note: {server.source_line}",
                            ],
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
                        status=RuleStatus.FAILED,
                        finding=f"{who} is on a different subnet than the stated "
                        f"DHCP server {server.ip_address}, but has no "
                        "ip helper-address configured to relay DHCP requests to it.",
                        evidence=[
                            f"{who} IP/mask: {iface.ip_address}/{iface.subnet_mask} "
                            f"-> subnet {network}",
                            f"topology_note: {server.source_line}",
                            f"{server.ip_address} is NOT a member of {network}",
                            f"running-config for {iface.interface}: no "
                            "'ip helper-address' line present",
                        ],
                        severity="Critical",
                        recommended_next_command=None,
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# RULE_13 - DHCP Excluded-Address / Binding Conflict
# ---------------------------------------------------------------------------


def check_excluded_address_conflict(
    case: NetworkCase, evidence: ParsedEvidence
) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_13", "DHCP Excluded-Address / Binding Conflict"
    findings: list[RuleFinding] = []

    pools_with_router = [p for p in evidence.dhcp_pool_configs if p.default_router]

    if not pools_with_router:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No DHCP pool configuration with a default-router setting "
                "is available.",
                evidence=[],
                severity=None,
                recommended_next_command="show running-config | section dhcp",
            )
        )
        return findings

    if not evidence.dhcp_bindings:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A DHCP pool's default-router is known, but no "
                "'show ip dhcp binding' output is available to confirm whether "
                "that IP has been leased to a client.",
                evidence=[p.source_block for p in pools_with_router],
                severity=None,
                recommended_next_command="show ip dhcp binding",
            )
        )
        return findings

    bound_ips = {b.ip_address for b in evidence.dhcp_bindings}
    for pool in pools_with_router:
        who = f"pool {pool.pool_name or '(unknown)'} on {pool.device or 'the DHCP server'}"
        if pool.default_router in bound_ips:
            findings.append(
                RuleFinding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who}'s default-router IP {pool.default_router} has "
                    "been leased to a client -- it is not excluded from the pool.",
                    evidence=[
                        pool.source_block,
                        f"show ip dhcp binding shows a lease for {pool.default_router}",
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
                    finding=f"{who}'s default-router IP {pool.default_router} has "
                    "not been leased to any client.",
                    evidence=[f"show ip dhcp binding does not list {pool.default_router}"],
                    severity=None,
                    recommended_next_command=None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RULE_14 - DHCP Global Service Validation
# ---------------------------------------------------------------------------


def check_global_service(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    rule_id, rule_name = "RULE_14", "DHCP Global Service Validation"
    findings: list[RuleFinding] = []

    if evidence.dhcp_service_enabled is None:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'service dhcp' / 'no service dhcp' line was found in "
                "the evidence for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show running-config | include dhcp",
            )
        )
    elif evidence.dhcp_service_enabled is False:
        findings.append(
            RuleFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                category=CATEGORY,
                status=RuleStatus.FAILED,
                finding="Global DHCP service is disabled ('no service dhcp'), so "
                "no DHCP pool on this device can respond to requests.",
                evidence=["running-config contains: no service dhcp"],
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
                finding="Global DHCP service is explicitly enabled ('service dhcp').",
                evidence=["running-config contains: service dhcp"],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    """Aggregate entry point so rule_checker.py can treat this as one module."""
    return (
        check_pool_exhaustion(case, evidence)
        + check_relay_helper_address(case, evidence)
        + check_excluded_address_conflict(case, evidence)
        + check_global_service(case, evidence)
    )
