"""
gateway_validation.py
----------------------
RULE_03: Default Gateway Validation

Detects two deterministic gateway problems, in this order:

  1. Gateway outside local subnet
     Requires: host IP + host subnet mask + configured default gateway.
     Pure arithmetic (ipaddress module) -- no external "expected" value
     needed. Covers CASE_007 and CASE_009 in the real dataset.

  2. Incorrect gateway vs. an explicitly stated authoritative gateway
     Some topology_notes state the "true" gateway explicitly, e.g.
     "Gateway R1 Gi0/0 IP: 192.168.1.1". If a host's configured gateway
     is IN-subnet but does not match that stated value, this is an
     "incorrect gateway" finding (spec: "Incorrect gateway where expected
     gateway information is explicitly available"). Covers CASE_006.

If host IP, mask, or gateway is missing, the rule returns
INSUFFICIENT_EVIDENCE rather than guessing -- per the project's core
principle, we never infer a gateway problem from a bare connectivity
symptom alone.
"""

from __future__ import annotations

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
from ai_troubleshooter.rules.base import (
    host_network,
    ip_in_network,
    is_valid_ipv4
)  # noqa: E402

RULE_ID = "RULE_03"
RULE_NAME = "Default Gateway Validation"
CATEGORY = "Gateway"

_STATED_GATEWAY_RE = re.compile(
    r"Gateway\s+\S+\s+\S+\s+IP:\s*(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)


def _stated_gateway(topology_note: str) -> str | None:
    m = _STATED_GATEWAY_RE.search(topology_note)
    return m.group(1) if m else None


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    findings: list[RuleFinding] = []

    # Only configs that actually carry a default_gateway field are relevant here.
    hosts_with_gateway = [c for c in evidence.ip_configs if c.default_gateway]

    if not hosts_with_gateway:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No host default-gateway configuration was found in this case.",
                evidence=[],
                severity=None,
                recommended_next_command="ipconfig",
            )
        )
        return findings

    stated_gw = _stated_gateway(case.topology_note)

    for host in hosts_with_gateway:
        who = host.device or "host"
        mask_or_prefix = host.subnet_mask or host.prefix_len

        if not host.ip_address or not mask_or_prefix:
            findings.append(
                RuleFinding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    category=CATEGORY,
                    status=RuleStatus.INSUFFICIENT_EVIDENCE,
                    finding=f"{who} has a configured gateway but its IP address and/or "
                    "subnet mask were not both found, so subnet membership cannot be checked.",
                    evidence=[host.source_line],
                    severity=None,
                    recommended_next_command="ipconfig",
                )
            )
            continue

        network = host_network(host.ip_address, mask_or_prefix)
        if network is None:
            # IP/mask malformed -- IP/Subnet rules already flag this; don't double-report.
            continue

        in_subnet = ip_in_network(host.default_gateway, network)
        if in_subnet is None:
            continue  # malformed gateway IP -- RULE_01 already flags this

        if not in_subnet:
            findings.append(
                RuleFinding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"Default gateway {host.default_gateway} configured on {who} "
                    f"is outside {who}'s local subnet {network}.",
                    evidence=[
                        f"{who} IP/mask: {host.ip_address}/{mask_or_prefix} -> subnet {network}",
                        f"{who} default gateway: {host.default_gateway}",
                        f"{host.default_gateway} is NOT a member of {network}",
                    ],
                    severity="High",
                    recommended_next_command=None,
                )
            )
        elif stated_gw and stated_gw != host.default_gateway:
            findings.append(
                RuleFinding(
                    rule_id=RULE_ID,
                    rule_name=RULE_NAME,
                    category=CATEGORY,
                    status=RuleStatus.FAILED,
                    finding=f"{who} is configured with gateway {host.default_gateway}, "
                    f"but the expected gateway per topology is {stated_gw}.",
                    evidence=[
                        f"topology_note states expected gateway: {stated_gw}",
                        f"{who} configured gateway (ipconfig): {host.default_gateway}",
                    ],
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
                    finding=f"Default gateway {host.default_gateway} configured on {who} "
                    f"is within {who}'s local subnet {network}.",
                    evidence=[
                        f"{who} IP/mask: {host.ip_address}/{mask_or_prefix} -> subnet {network}",
                        f"{host.default_gateway} is a member of {network}",
                    ],
                    severity=None,
                    recommended_next_command=None,
                )
            )

    return findings
