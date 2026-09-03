"""
subnet_validation.py
---------------------
RULE_02: Subnet Mask Validation

Checks that every subnet mask found in the evidence (from `ipconfig`
blocks, or a /prefix on a router interface) is a valid, contiguous IPv4
mask.

Deterministic scope:
The current dataset's masks are all valid dotted-decimal masks (e.g.
255.255.255.0, 255.255.255.240) or valid /prefixes -- it never places an
address on a network whose mask itself is malformed (e.g. 255.255.255.15).
So, like RULE_01, this rule PASSes on the real dataset today; the FAILED
path is proven with a synthetic test in tests/test_rules.py.

This rule intentionally does NOT check "does this host's subnet match
its gateway's subnet" -- that cross-field consistency check is Gateway
Validation's job (gateway_validation.py, RULE_03), because it needs both
the mask AND the gateway to mean anything.
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
    is_valid_ipv4_mask
)  # noqa: E402

RULE_ID = "RULE_02"
RULE_NAME = "Subnet Mask Validation"
CATEGORY = "Subnet"


def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
    findings: list[RuleFinding] = []

    masks: list[tuple[str, str]] = []  # (mask_str, description)
    for cfg in evidence.ip_configs:
        if cfg.subnet_mask:
            who = cfg.device or cfg.interface or "host"
            masks.append((cfg.subnet_mask, f"subnet mask configured on {who}"))
        elif cfg.prefix_len is not None:
            who = cfg.device or cfg.interface or "host"
            masks.append((f"/{cfg.prefix_len}", f"prefix length configured on {who}"))

    if not masks:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.INSUFFICIENT_EVIDENCE,
                finding="No subnet mask or prefix-length evidence was found in this case.",
                evidence=[],
                severity=None,
                recommended_next_command="ipconfig",
            )
        )
        return findings

    bad: list[tuple[str, str]] = []
    good: list[tuple[str, str]] = []
    for mask, desc in masks:
        if mask.startswith("/"):
            prefix = int(mask[1:])
            valid = 0 <= prefix <= 32
        else:
            valid = is_valid_ipv4_mask(mask)
        (good if valid else bad).append((mask, desc))

    if bad:
        findings.append(
            RuleFinding(
                rule_id=RULE_ID,
                rule_name=RULE_NAME,
                category=CATEGORY,
                status=RuleStatus.FAILED,
                finding=f"{len(bad)} invalid subnet mask(es)/prefix(es) found in the supplied evidence.",
                evidence=[f"'{m}' ({d}) is not a valid subnet mask." for m, d in bad],
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
                finding=f"All {len(good)} subnet mask(es)/prefix(es) found in the evidence are valid.",
                evidence=[f"'{m}' ({d}) is a valid subnet mask." for m, d in good],
                severity=None,
                recommended_next_command=None,
            )
        )
    return findings
