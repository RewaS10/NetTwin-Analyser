"""
base.py
-------
Shared networking utility functions and the common Rule interface.

Keeping IP/mask arithmetic here (instead of duplicating it in every rule
module) means every rule that needs "is this a valid IP" or "is this
gateway inside this subnet" calls the exact same, once-tested logic.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Protocol

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import NetworkCase, ParsedEvidence, RuleFinding  # noqa: E402


# ---------------------------------------------------------------------------
# IP / subnet arithmetic helpers
# ---------------------------------------------------------------------------


def is_valid_ipv4(value: Optional[str]) -> bool:
    """True only for a syntactically valid IPv4 address (e.g. 192.168.1.1)."""
    if not value:
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_valid_ipv4_mask(value: Optional[str]) -> bool:
    """
    True only for a valid, contiguous IPv4 subnet mask (e.g. 255.255.255.0).
    Rejects malformed masks like 255.255.255.15 (non-contiguous bits) or
    plain garbage strings.
    """
    if not value:
        return False
    try:
        # netmask=True forces ipaddress to validate contiguity.
        ipaddress.IPv4Network(f"0.0.0.0/{value}", strict=False)
        return True
    except ValueError:
        return False


def mask_to_prefix(mask: str) -> Optional[int]:
    """Convert a dotted-decimal mask to a prefix length, or None if invalid."""
    if not is_valid_ipv4_mask(mask):
        return None
    net = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
    return net.prefixlen


def host_network(ip: str, mask_or_prefix) -> Optional[ipaddress.IPv4Network]:
    """
    Return the IPv4Network that `ip` belongs to, given either a dotted mask
    (e.g. '255.255.255.0') or a prefix length (e.g. 24). Returns None if the
    inputs are not valid.
    """
    if not is_valid_ipv4(ip):
        return None
    try:
        if isinstance(mask_or_prefix, int):
            return ipaddress.IPv4Network(f"{ip}/{mask_or_prefix}", strict=False)
        if is_valid_ipv4_mask(mask_or_prefix):
            prefix = mask_to_prefix(mask_or_prefix)
            return ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None
    return None


def ip_in_network(ip: str, network: ipaddress.IPv4Network) -> Optional[bool]:
    """True/False if determinable, None if `ip` itself is malformed."""
    if not is_valid_ipv4(ip):
        return None
    return ipaddress.IPv4Address(ip) in network


# ---------------------------------------------------------------------------
# Interface-name helpers
# ---------------------------------------------------------------------------

_IFACE_TYPE_ALIASES = {
    "gi": "gigabitethernet",
    "gig": "gigabitethernet",
    "ge": "gigabitethernet",
    "gigabitethernet": "gigabitethernet",
    "fa": "fastethernet",
    "fastethernet": "fastethernet",
    "se": "serial",
    "serial": "serial",
    "et": "ethernet",
    "eth": "ethernet",
    "ethernet": "ethernet",
    "te": "tengigabitethernet",
    "tengigabitethernet": "tengigabitethernet",
}
_IFACE_NAME_RE = re.compile(r"^\s*([A-Za-z]+)\s*(\d+(?:/\d+)*)\s*$")


def normalize_interface_name(name: Optional[str]) -> Optional[str]:
    """
    Canonicalize a Cisco interface name/abbreviation (e.g. 'Gi0/0' or
    'GigabitEthernet0/0') to '<full type><slot/port>' so abbreviated and
    fully-spelled forms of the same interface compare equal. Returns None
    for an unrecognized interface-type prefix or malformed input.
    """
    if not name:
        return None
    m = _IFACE_NAME_RE.match(name)
    if not m:
        return None
    prefix, rest = m.groups()
    canon = _IFACE_TYPE_ALIASES.get(prefix.lower())
    if canon is None:
        return None
    return f"{canon}{rest}"


def same_interface(a: Optional[str], b: Optional[str]) -> bool:
    """True if two interface names/abbreviations refer to the same interface."""
    na, nb = normalize_interface_name(a), normalize_interface_name(b)
    return na is not None and na == nb


# ---------------------------------------------------------------------------
# Rule interface
# ---------------------------------------------------------------------------


class Rule(Protocol):
    """
    Every rule module exposes one function matching this signature:

        def check(case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]

    A rule may return zero findings (e.g. it doesn't apply to this case's
    concept_tag at all), or one finding per relevant piece of evidence
    (e.g. one HostIPConfig might trigger a separate Gateway finding for
    each host found in the case).
    """

    def check(self, case: NetworkCase, evidence: ParsedEvidence) -> list[RuleFinding]:
        ...
