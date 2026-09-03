"""
routing_validation.py
------------------------
RULE_10: Routing Validation (missing route to a stated remote LAN)

Deterministic check: topology_note states which router owns which LAN
(e.g. "R2 LAN: 172.16.30.0/24" or "R1 LAN 192.168.10.0/24"). For any
router whose route table was captured (`show ip route` / `show ip route
static`, even if that table turned out to be empty), we check that every
OTHER router's stated LAN network appears among this router's own route
entries (connected or static). If it's absent, that's a deterministic
"missing route" finding -- the evidence directly shows the destination
network is not in the table, per the project's core principle (never
infer "route missing" from a bare connectivity symptom alone).

Covers, in the real dataset:
  - CASE_018: R1's route table lacks a route to R2's LAN (172.16.30.0/24).
  - CASE_021: R2's route table (present but empty) lacks a route to R1's
    LAN (192.168.10.0/24); R1's table correctly has a route to R2's LAN.

Explicitly OUT of scope for this rule (see IMPLEMENTATION_PLAN.md):
CASE_019 and CASE_020 are OSPF adjacency/network-statement problems --
they have no `show ip route` output to check at all (only `show ip ospf
neighbor` / running-config OSPF excerpts), so this rule correctly reports
INSUFFICIENT_EVIDENCE for them rather than inventing an OSPF-specific
check under the "Routing" rule ID.

This rule also does NOT validate next-hop correctness (the spec's
"incorrect next hop" case) -- the dataset provides no case where a route
exists but points to a demonstrably wrong next hop, so that check is not
implemented (see IMPLEMENTATION_PLAN.md's "Not implementable" notes).
"""

from __future__ import annotations

import ipaddress
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_troubleshooter.models import (
    NetworkCase,
    ParsedEvidence,
    RuleFinding,
    RuleStatus
)  # noqa: E402

RULE_ID = "RULE_10"
RULE_NAME = "Routing Validation"
CATEGORY = "Routing"


def _same_network(a: str, b: str) -> bool:
    try:
        return ipaddress.IPv4Network(a, strict=False) == ipaddress.IPv4Network(b, strict=False)
    except ValueError:
        return a == b


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    findings: list[RuleFinding] = []

    if not evidence.routed_devices:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No 'show ip route' or 'show ip route static' output is "
                "available for this case.",
                evidence=[],
                severity=None,
                recommended_next_command="show ip route",
            )
        )
        return findings

    if not evidence.lan_bindings:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="A route table is available, but the topology notes do not "
                "state which router owns which LAN network, so it cannot be "
                "determined which destination networks each router is expected to reach.",
                evidence=[
                    f"{d} has a route table with "
                    f"{len([e for e in evidence.route_entries if e.device == d])} entrie(s)"
                    for d in evidence.routed_devices
                ],
                severity=None,
                recommended_next_command=None,
            )
        )
        return findings

    for device in evidence.routed_devices:
        device_entries = [e for e in evidence.route_entries if e.device == device]
        device_networks = [e.network for e in device_entries]

        # Every OTHER router's stated LAN should be reachable from this router's table.
        remote_lans = [b for b in evidence.lan_bindings if b.router != device]

        if not remote_lans:
            continue  # nothing to check for this device

        for lan in remote_lans:
            present = any(_same_network(lan.network, net) for net in device_networks)
            if present:
                findings.append(
                    RuleFinding(
                        rule_id=RULE_ID,
                        rule_name=RULE_NAME,
                        category=CATEGORY,
                        status=RuleStatus.PASS,
                        finding=f"{device}'s route table contains a route to "
                        f"{lan.router}'s LAN network {lan.network}.",
                        evidence=[
                            e.source_line
                            for e in device_entries
                            if _same_network(lan.network, e.network)
                        ],
                        severity=None,
                        recommended_next_command=None,
                    )
                )
            else:
                findings.append(
                    RuleFinding(
                        rule_id=RULE_ID,
                        rule_name=RULE_NAME,
                        category=CATEGORY,
                        status=RuleStatus.FAILED,
                        finding=f"{device} is missing a route to {lan.router}'s LAN "
                        f"network {lan.network}.",
                        evidence=[
                            f"topology_note: {lan.source_line}",
                            f"{device}'s route table entries: {device_networks or '(empty)'}",
                            f"{lan.network} does not appear in {device}'s route table",
                        ],
                        severity="High",
                        recommended_next_command=None,
                    )
                )
    return findings
