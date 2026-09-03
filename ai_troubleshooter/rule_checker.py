"""
rule_checker.py
-----------------
The Rule-Based Troubleshooting Engine's orchestrator.

    case = load_case("CASE_001")
    result = run(case)
    print(result.model_dump_json(indent=2))

or, for the whole dataset:

    for result in run_all():
        ...

Responsibilities:
- Load NetworkCase rows from data/cases.csv (no manual re-typing of cases
  into Python, per the project's dataset-integration requirement).
- Run the evidence analyzer once per case.
- Run every implemented rule module against that evidence, in the
  priority order specified by the project brief:
    1. IP/subnet validation
    2. Interface status
    3. Gateway validation
    4. VLAN validation
    5. Trunk / Routing / DHCP / NAT / ACL validation
  (Only the categories implemented so far -- see IMPLEMENTATION_PLAN.md
  for the remaining categories: Segmentation, Port Security.)
- Return one RuleResult per case containing every RuleFinding produced.

This module deliberately contains NO networking logic itself -- all
domain logic lives in rules/*.py and evidence_analyzer.py. This keeps the
orchestrator trivial to read and test.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path

from ai_troubleshooter.evidence_analyzer import parse_case
from ai_troubleshooter.models import NetworkCase, RuleResult
from ai_troubleshooter.rules import (
    acl_validation,
    dhcp_validation,
    gateway_validation,
    interface_status,
    ip_validation,
    nat_validation,
    routing_validation,
    subnet_validation,
    trunk_validation,
    vlan_validation,
)

_THIS_DIR = Path(__file__).resolve().parent
_DEFAULT_DATA_PATH = _THIS_DIR.parent / "data" / "cases.csv"

# Priority order per the project brief. Each entry is a rule module
# exposing check(case, evidence) -> list[RuleFinding].
_RULE_MODULES = [
    ip_validation,        # 1. Input/evidence validation
    subnet_validation,    # 1. Input/evidence validation
    interface_status,     # 2. Interface status
    gateway_validation,   # 5. Gateway validation
    vlan_validation,      # 4. VLAN/access/trunk validation
    trunk_validation,     # 4. VLAN/access/trunk validation
    routing_validation,   # 6. Routing validation
    dhcp_validation,       # 7. DHCP/DNS/NAT validation
    nat_validation,        # 7. DHCP/DNS/NAT validation
    acl_validation,        # 8. ACL validation
]


def load_all_cases(path: str | os.PathLike = _DEFAULT_DATA_PATH) -> list[NetworkCase]:
    """Load every case from data/cases.csv into validated NetworkCase objects."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [NetworkCase(**row) for row in reader]


def load_case(case_id: str, path: str | os.PathLike = _DEFAULT_DATA_PATH) -> NetworkCase:
    """Load a single case by its case_id."""
    for case in load_all_cases(path):
        if case.case_id == case_id:
            return case
    raise KeyError(f"No case with case_id={case_id!r} found in {path}")


def run(case: NetworkCase) -> RuleResult:
    """Run every implemented rule against a single case."""
    evidence = parse_case(case)
    findings = []
    for module in _RULE_MODULES:
        findings.extend(module.check(case, evidence))
    return RuleResult(case_id=case.case_id, rule_findings=findings)


def run_all(path: str | os.PathLike = _DEFAULT_DATA_PATH) -> list[RuleResult]:
    """Run every implemented rule against every case in the dataset."""
    return [run(case) for case in load_all_cases(path)]


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        result = run(load_case(sys.argv[1]))
        print(result.model_dump_json(indent=2))
    else:
        for result in run_all():
            print(f"\n=== {result.case_id} ===")
            for finding in result.rule_findings:
                print(f"  [{finding.rule_id}] {finding.rule_name}: {finding.status}")
                print(f"      {finding.finding}")
