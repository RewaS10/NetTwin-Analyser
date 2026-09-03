"""
Evidence Analyzer
=================

The real dataset does NOT provide structured per-field evidence (no
separate "host_ip" / "gateway_ip" / "vlan_id" columns). Every case packs
its evidence into free-text Cisco CLI output inside `show_outputs`, plus
a few explicit facts written in plain English inside `topology_note` and
`symptom`.

This module is the ONLY place that touches that raw text. Its job is to
turn raw text into the normalized `ParsedEvidence` structures defined in
models.py. Rules never regex the raw text themselves — they only read
ParsedEvidence. This keeps parsing centralized, testable, and separate
from rule logic (rule_checker.py).

Design principle carried over from the rule engine itself: if a pattern
is not clearly present in the text, we do not guess. An empty/absent
field in ParsedEvidence means "not found" — it is up to each rule to
decide that this means INSUFFICIENT_EVIDENCE.
"""

from __future__ import annotations

import re

from ai_troubleshooter.models import (
    AclInterfaceBinding,
    DhcpBindingEntry,
    DhcpInterfaceConfig,
    DhcpPoolConfig,
    DhcpPoolStats,
    ExtendedAclEntry,
    ExtendedAclLine,
    HostIPConfig,
    IntendedVlanBinding,
    InterfaceBriefEntry,
    LanBinding,
    NatInsideSourceRule,
    NatPoolInfo,
    NatStatistics,
    NetworkCase,
    ParsedEvidence,
    RouteTableEntry,
    RunningConfigVlanAssignment,
    StandardAclEntry,
    StatedDhcpServer,
    StatedLanSubnet,
    SwitchportInfo,
    TrunkInfo,
    VlanBriefEntry,
) 

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEVICE_PROMPT_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*[>#]")


def _split_paragraphs(text: str) -> list[str]:
    """Split raw show_outputs on blank lines into loosely-related chunks."""
    chunks = re.split(r"\n\s*\n", text.strip())
    return [c for c in chunks if c.strip()]


def _device_of(chunk: str) -> str | None:
    m = _DEVICE_PROMPT_RE.search(chunk.splitlines()[0]) if chunk.splitlines() else None
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Individual parsers
# ---------------------------------------------------------------------------


def _parse_ipconfig_blocks(chunks: list[str]) -> list[HostIPConfig]:
    """Parse PC-style `ipconfig` blocks: IP Address / Subnet Mask / Default Gateway."""
    results: list[HostIPConfig] = []
    for chunk in chunks:
        if "ipconfig" not in chunk.lower() and "IP Address" not in chunk:
            continue
        ip_m = re.search(r"IP Address[.\s]*:\s*([\d.]+)", chunk)
        mask_m = re.search(r"Subnet Mask[.\s]*:\s*([\d.]+)", chunk)
        gw_m = re.search(r"Default Gateway[.\s]*:\s*([\d.]+)", chunk)
        if not (ip_m or mask_m or gw_m):
            continue
        results.append(
            HostIPConfig(
                source_line=chunk.strip(),
                device=_device_of(chunk),
                ip_address=ip_m.group(1) if ip_m else None,
                subnet_mask=mask_m.group(1) if mask_m else None,
                default_gateway=gw_m.group(1) if gw_m else None,
            )
        )
    return results


def _parse_show_ip_interface_single(chunks: list[str]) -> list[HostIPConfig]:
    """Parse `show ip interface <if>` blocks: 'Internet address is X/Y'."""
    results: list[HostIPConfig] = []
    for chunk in chunks:
        cmd_m = re.search(r"show ip interface\s+(\S+)(?!\s+brief)", chunk)
        addr_m = re.search(r"Internet address is\s+([\d.]+)/(\d+)", chunk)
        if not (cmd_m and addr_m) or "brief" in chunk.lower():
            continue
        results.append(
            HostIPConfig(
                source_line=chunk.strip(),
                device=_device_of(chunk),
                interface=cmd_m.group(1),
                ip_address=addr_m.group(1),
                prefix_len=int(addr_m.group(2)),
            )
        )
    return results


_IFACE_BRIEF_ROW_RE = re.compile(
    r"^(?P<iface>\S+)\s+(?P<ip>\S+)\s+\S+\s+\S+\s+(?P<rest>.+)$"
)


def _parse_interface_brief(chunks: list[str]) -> list[InterfaceBriefEntry]:
    """Parse `show ip interface brief` tables."""
    results: list[InterfaceBriefEntry] = []
    for chunk in chunks:
        if "show ip interface brief" not in chunk and "Protocol" not in chunk:
            continue
        lines = chunk.splitlines()
        for line in lines:
            if not line.strip() or line.strip().startswith("Interface"):
                continue
            if "show ip interface brief" in line:
                continue
            m = _IFACE_BRIEF_ROW_RE.match(line.strip())
            if not m:
                continue
            rest_tokens = m.group("rest").split()
            if len(rest_tokens) < 2:
                continue
            protocol = rest_tokens[-1]
            status = " ".join(rest_tokens[:-1])
            if protocol not in ("up", "down"):
                continue
            results.append(
                InterfaceBriefEntry(
                    interface=m.group("iface"),
                    ip_address=m.group("ip"),
                    status=status,
                    protocol=protocol,
                    source_line=line.strip(),
                )
            )
    return results


_VLAN_BRIEF_ROW_RE = re.compile(r"^(\d+)\s+(\S.*?)\s{2,}(\S+)\s+(.*)$")


def _parse_vlan_brief(chunks: list[str]) -> list[VlanBriefEntry]:
    """Parse `show vlan brief` tables."""
    results: list[VlanBriefEntry] = []
    for chunk in chunks:
        if "show vlan brief" not in chunk and "VLAN Name" not in chunk:
            continue
        for line in chunk.splitlines():
            if line.strip().startswith(("VLAN", "----", "SW", "R")):
                continue
            m = _VLAN_BRIEF_ROW_RE.match(line.rstrip())
            if not m:
                continue
            vlan_id, name, status, ports_raw = m.groups()
            ports = [p.strip() for p in ports_raw.split(",") if p.strip()]
            results.append(
                VlanBriefEntry(
                    vlan_id=int(vlan_id),
                    name=name.strip(),
                    status=status.strip(),
                    ports=ports,
                    source_line=line.strip(),
                )
            )
    return results


def _parse_switchport_blocks(chunks: list[str]) -> list[SwitchportInfo]:
    """Parse `show interfaces <if> switchport` blocks."""
    results: list[SwitchportInfo] = []
    for chunk in chunks:
        if "switchport" not in chunk.lower() or "show interfaces" not in chunk.lower():
            continue
        if "trunk\n" in chunk.lower() and "vlans allowed" in chunk.lower():
            # This is a `show interfaces trunk` block, handled separately.
            continue
        cmd_m = re.search(
            r"show interfaces\s+(.+?)\s+switchport", chunk, flags=re.IGNORECASE
        )
        admin_mode_m = re.search(r"Administrative Mode:\s*(.+)", chunk)
        oper_mode_m = re.search(r"Operational Mode:\s*(.+)", chunk)
        access_vlan_m = re.search(r"Access Mode VLAN:\s*(\d+)", chunk)
        admin_native_m = re.search(r"Administrative Native VLAN:\s*(\d+)", chunk)
        oper_native_m = re.search(r"Operational Native VLAN:\s*(\d+)", chunk)
        if not any(
            [admin_mode_m, oper_mode_m, access_vlan_m, admin_native_m, oper_native_m]
        ):
            continue
        results.append(
            SwitchportInfo(
                device=_device_of(chunk),
                interface=cmd_m.group(1).strip() if cmd_m else None,
                administrative_mode=(
                    admin_mode_m.group(1).strip() if admin_mode_m else None
                ),
                operational_mode=oper_mode_m.group(1).strip() if oper_mode_m else None,
                access_vlan=int(access_vlan_m.group(1)) if access_vlan_m else None,
                administrative_native_vlan=(
                    int(admin_native_m.group(1)) if admin_native_m else None
                ),
                operational_native_vlan=(
                    int(oper_native_m.group(1)) if oper_native_m else None
                ),
                source_block=chunk.strip(),
            )
        )
    return results


def _parse_trunk_blocks(chunks: list[str]) -> list[TrunkInfo]:
    """Parse `show interfaces trunk` blocks."""
    results: list[TrunkInfo] = []
    for chunk in chunks:
        if "show interfaces trunk" not in chunk.lower():
            continue
        device = _device_of(chunk)
        lines = chunk.splitlines()
        native_vlan = None
        port = None
        # First table: Port / Mode / Encapsulation / Status / Native vlan
        for i, line in enumerate(lines):
            if line.strip().startswith("Port") and "Native vlan" in line:
                if i + 1 < len(lines):
                    row = lines[i + 1].split()
                    if row:
                        port = row[0]
                        native_vlan = int(row[-1]) if row[-1].isdigit() else None
                break
        allowed_vlans: list[int] = []
        for i, line in enumerate(lines):
            if "Vlans allowed on trunk" in line:
                if i + 1 < len(lines):
                    row = lines[i + 1].split(None, 1)
                    if len(row) == 2:
                        port = port or row[0]
                        allowed_vlans = [
                            int(v) for v in re.findall(r"\d+", row[1])
                        ]
                break
        if port is None and native_vlan is None and not allowed_vlans:
            continue
        results.append(
            TrunkInfo(
                device=device,
                port=port,
                native_vlan=native_vlan,
                allowed_vlans=allowed_vlans,
                source_block=chunk.strip(),
            )
        )
    return results


def _parse_intended_vlan_bindings(topology_note: str) -> list[IntendedVlanBinding]:
    """Parse 'on Fa0/1 (intended VLAN 20)' style statements from topology notes."""
    results = []
    for m in re.finditer(
        r"on\s+(\S+?)\s*\(intended VLAN\s*(\d+)\)", topology_note, flags=re.IGNORECASE
    ):
        results.append(
            IntendedVlanBinding(
                port=m.group(1).rstrip(").,"),
                intended_vlan=int(m.group(2)),
                source_line=m.group(0),
            )
        )
    return results


def _parse_running_config_vlan_assignments(
    chunks: list[str],
) -> list[RunningConfigVlanAssignment]:
    results: list[RunningConfigVlanAssignment] = []
    for chunk in chunks:
        if "switchport access vlan" not in chunk.lower():
            continue
        iface_m = re.search(r"interface\s+(\S+)", chunk)
        for m in re.finditer(r"switchport access vlan\s+(\d+)", chunk, flags=re.IGNORECASE):
            results.append(
                RunningConfigVlanAssignment(
                    interface=iface_m.group(1) if iface_m else None,
                    vlan_id=int(m.group(1)),
                    source_line=m.group(0),
                )
            )
    return results


def _parse_mentioned_vlans(*texts: str) -> list[int]:
    found: list[int] = []
    for text in texts:
        for m in re.finditer(r"VLAN\s*(\d+)", text, flags=re.IGNORECASE):
            vlan_id = int(m.group(1))
            if vlan_id not in found:
                found.append(vlan_id)
    return found


def _split_by_device_prompt(text: str) -> list[str]:
    """
    Split raw show_outputs into segments, each starting at a device-prompt
    line (e.g. 'R1# show ip route') and running until the next prompt line.

    Unlike _split_paragraphs, this does NOT break a segment on a blank
    line -- some classic IOS route-table captures in this dataset contain
    a blank line between the 'Gateway of last resort' banner and the
    subnetted/route lines that follow, and that blank line is still part
    of the same `show ip route` output.
    """
    lines = text.splitlines()
    segments: list[str] = []
    current: list[str] = []
    for line in lines:
        if _DEVICE_PROMPT_RE.match(line) and current:
            segments.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        segments.append("\n".join(current))
    return [s for s in segments if s.strip()]


def _parse_stated_subnets(topology_note: str) -> list[str]:
    found: list[str] = []
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})", topology_note):
        cidr = f"{m.group(1)}/{m.group(2)}"
        if cidr not in found:
            found.append(cidr)
    return found


_ROUTE_CMD_RE = re.compile(r"show ip route(\s+static)?\b", re.IGNORECASE)
_SUBNETTED_RE = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\s+is subnetted", re.IGNORECASE
)
# Matches route-table lines like:
#   C       10.0.0.0 is directly connected, GigabitEthernet0/1
#   S    192.168.20.0/24 [1/0] via 10.0.0.2
_ROUTE_LINE_RE = re.compile(
    r"^(?P<code>[A-Z]\*?)\s+(?P<net>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<prefix>\d{1,2}))?\b"
)


def _parse_route_tables(chunks: list[str]) -> tuple[list[RouteTableEntry], list[str]]:
    """
    Parse `show ip route` / `show ip route static` blocks.

    Handles both classic IOS style (a separate "X.X.X.X/N is subnetted" line
    followed by bare-network C/S lines) and the simpler modern style where
    the CIDR prefix is inline on the route line itself. Returns the parsed
    entries plus the list of devices that issued a route-table command at
    all (even if the resulting table has zero entries -- an empty table is
    still valid evidence, not missing evidence).
    """
    entries: list[RouteTableEntry] = []
    routed_devices: list[str] = []
    for chunk in chunks:
        if not _ROUTE_CMD_RE.search(chunk):
            continue
        device = _device_of(chunk)
        if device and device not in routed_devices:
            routed_devices.append(device)

        current_prefix: dict[str, int] = {}
        for line in chunk.splitlines():
            subnetted_m = _SUBNETTED_RE.match(line.strip())
            if subnetted_m:
                base_net, prefix = subnetted_m.groups()
                current_prefix[base_net] = int(prefix)
                continue

            route_m = _ROUTE_LINE_RE.match(line.strip())
            if not route_m:
                continue
            code = route_m.group("code")
            net = route_m.group("net")
            prefix = route_m.group("prefix")
            if prefix is None:
                prefix = current_prefix.get(net)
            if prefix is None:
                # No prefix known for this bare network -- skip rather than guess.
                continue
            entries.append(
                RouteTableEntry(
                    device=device,
                    network=f"{net}/{prefix}",
                    code=code.rstrip("*"),
                    source_line=line.strip(),
                )
            )
    return entries, routed_devices


_LAN_BINDING_RE = re.compile(
    r"(\S+)\s+LAN:?\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", re.IGNORECASE
)


def _parse_lan_bindings(topology_note: str) -> list[LanBinding]:
    """Parse statements like 'R2 LAN: 172.16.30.0/24' or 'R1 LAN 192.168.10.0/24'."""
    results: list[LanBinding] = []
    for m in re.finditer(_LAN_BINDING_RE, topology_note):
        results.append(
            LanBinding(
                router=m.group(1).rstrip(",."),
                network=m.group(2),
                source_line=m.group(0),
            )
        )
    return results


# ---------------------------------------------------------------------------
# DHCP parsers
# ---------------------------------------------------------------------------

_DHCP_POOL_STATS_CMD_RE = re.compile(r"show ip dhcp pool\s+(\S+)", re.IGNORECASE)
_TOTAL_ADDR_RE = re.compile(r"Total addresses\s*:\s*(\d+)", re.IGNORECASE)
_LEASED_ADDR_RE = re.compile(r"Leased addresses\s*:\s*(\d+)", re.IGNORECASE)


def _parse_dhcp_pool_stats(segments: list[str]) -> list[DhcpPoolStats]:
    """Parse `show ip dhcp pool <name>` utilization blocks (e.g. CASE_010)."""
    results: list[DhcpPoolStats] = []
    for seg in segments:
        cmd_m = _DHCP_POOL_STATS_CMD_RE.search(seg)
        if not cmd_m:
            continue
        total_m = _TOTAL_ADDR_RE.search(seg)
        leased_m = _LEASED_ADDR_RE.search(seg)
        if not (total_m or leased_m):
            continue
        results.append(
            DhcpPoolStats(
                device=_device_of(seg),
                pool_name=cmd_m.group(1),
                total_addresses=int(total_m.group(1)) if total_m else None,
                leased_addresses=int(leased_m.group(1)) if leased_m else None,
                source_block=seg.strip(),
            )
        )
    return results


_DHCP_POOL_CFG_RE = re.compile(r"^\s*ip dhcp pool\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
_DHCP_NETWORK_RE = re.compile(
    r"^\s*network\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE | re.MULTILINE,
)
_DHCP_DEFAULT_ROUTER_RE = re.compile(
    r"^\s*default-router\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE | re.MULTILINE
)


def _parse_dhcp_pool_configs(segments: list[str]) -> list[DhcpPoolConfig]:
    """
    Parse `ip dhcp pool <name>` blocks inside running-config excerpts
    (e.g. CASE_012, CASE_013). A pool's `network`/`default-router` lines
    are whatever comes after the `ip dhcp pool` line up to the next
    unindented line -- we simply search the whole segment for the first
    occurrence of each, since these excerpts only ever contain one pool.
    """
    results: list[DhcpPoolConfig] = []
    for seg in segments:
        pool_m = _DHCP_POOL_CFG_RE.search(seg)
        if not pool_m:
            continue
        net_m = _DHCP_NETWORK_RE.search(seg)
        router_m = _DHCP_DEFAULT_ROUTER_RE.search(seg)
        results.append(
            DhcpPoolConfig(
                device=_device_of(seg),
                pool_name=pool_m.group(1),
                network=f"{net_m.group(1)} {net_m.group(2)}" if net_m else None,
                default_router=router_m.group(1) if router_m else None,
                source_block=seg.strip(),
            )
        )
    return results


_DHCP_BINDING_ROW_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<rest>.+)$"
)


def _parse_dhcp_bindings(segments: list[str]) -> list[DhcpBindingEntry]:
    """Parse `show ip dhcp binding` tables."""
    results: list[DhcpBindingEntry] = []
    for seg in segments:
        if "show ip dhcp binding" not in seg.lower():
            continue
        device = _device_of(seg)
        for line in seg.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith("ip address"):
                continue
            m = _DHCP_BINDING_ROW_RE.match(stripped)
            if not m:
                continue
            # "rest" is whatever the table prints after the IP -- typically a
            # client-id/hardware-address token followed by type/expiration
            # text. We keep the first token as client_id and don't try to
            # parse expiration/type since no rule currently needs them.
            rest_tokens = m.group("rest").split()
            client_id = rest_tokens[0] if rest_tokens else None
            results.append(
                DhcpBindingEntry(
                    device=device,
                    ip_address=m.group("ip"),
                    client_id=client_id,
                    source_line=stripped,
                )
            )
    return results


_DHCP_IFACE_CMD_RE = re.compile(
    r"show running-config interface\s+(\S+)", re.IGNORECASE
)
_IFACE_IP_ADDR_RE = re.compile(
    r"^\s*ip address\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE | re.MULTILINE,
)
_HELPER_ADDR_RE = re.compile(
    r"ip helper-address\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)


def _parse_dhcp_interface_configs(segments: list[str]) -> list[DhcpInterfaceConfig]:
    """Parse `show running-config interface <if>` blocks (e.g. CASE_011)."""
    results: list[DhcpInterfaceConfig] = []
    for seg in segments:
        cmd_m = _DHCP_IFACE_CMD_RE.search(seg)
        if not cmd_m:
            continue
        ip_m = _IFACE_IP_ADDR_RE.search(seg)
        helpers = _HELPER_ADDR_RE.findall(seg)
        results.append(
            DhcpInterfaceConfig(
                device=_device_of(seg),
                interface=cmd_m.group(1),
                ip_address=ip_m.group(1) if ip_m else None,
                subnet_mask=ip_m.group(2) if ip_m else None,
                helper_addresses=helpers,
                source_block=seg.strip(),
            )
        )
    return results


_STATED_DHCP_SERVER_RE = re.compile(
    r"DHCP Server\s*\(?\s*(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)


def _parse_stated_dhcp_servers(topology_note: str) -> list[StatedDhcpServer]:
    """Parse statements like 'DHCP Server 10.0.2.100' or '(DHCP Server (10.0.2.100))'."""
    results: list[StatedDhcpServer] = []
    for m in _STATED_DHCP_SERVER_RE.finditer(topology_note):
        results.append(StatedDhcpServer(ip_address=m.group(1), source_line=m.group(0)))
    return results


_SERVICE_DHCP_RE = re.compile(r"^\s*(no\s+)?service dhcp\s*$", re.IGNORECASE | re.MULTILINE)


def _parse_dhcp_service_enabled(show_outputs: str) -> bool | None:
    """
    True if 'service dhcp' is explicitly confirmed enabled, False if 'no
    service dhcp' is found (globally disabled), None if neither line is
    present in the evidence at all.
    """
    m = _SERVICE_DHCP_RE.search(show_outputs)
    if not m:
        return None
    return m.group(1) is None


# ---------------------------------------------------------------------------
# NAT parsers
# ---------------------------------------------------------------------------

_NAT_STATS_CMD_RE = re.compile(r"show ip nat statistics", re.IGNORECASE)
_TOTAL_XLATE_RE = re.compile(r"Total active translations:\s*(\d+)", re.IGNORECASE)


def _parse_nat_statistics(chunks: list[str]) -> list[NatStatistics]:
    """Parse `show ip nat statistics` blocks (e.g. CASE_026)."""
    results: list[NatStatistics] = []
    for chunk in chunks:
        if not _NAT_STATS_CMD_RE.search(chunk):
            continue
        total_m = _TOTAL_XLATE_RE.search(chunk)
        outside: list[str] = []
        inside: list[str] = []
        outside_none = False
        inside_none = False
        section: str | None = None
        for raw_line in chunk.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.lower().startswith("outside interfaces"):
                section = "outside"
                continue
            if line.lower().startswith("inside interfaces"):
                section = "inside"
                continue
            if line.lower() == "none configured":
                if section == "outside":
                    outside_none = True
                elif section == "inside":
                    inside_none = True
                continue
            if section == "outside" and not line.lower().startswith("total active"):
                outside.append(line)
            elif section == "inside":
                inside.append(line)
        results.append(
            NatStatistics(
                device=_device_of(chunk),
                total_active_translations=int(total_m.group(1)) if total_m else None,
                outside_interfaces=outside,
                inside_interfaces=inside,
                outside_none_configured=outside_none,
                inside_none_configured=inside_none,
                source_block=chunk.strip(),
            )
        )
    return results


_NAT_INSIDE_SOURCE_RE = re.compile(
    r"ip nat inside source list\s+(\S+)\s+"
    r"(?:interface\s+(\S+)|pool\s+(\S+))"
    r"(\s+overload)?",
    re.IGNORECASE,
)


def _parse_nat_inside_source_rules(chunks: list[str]) -> list[NatInsideSourceRule]:
    """Parse `ip nat inside source list <acl> [interface <if> | pool <name>] [overload]` lines."""
    results: list[NatInsideSourceRule] = []
    for chunk in chunks:
        for m in _NAT_INSIDE_SOURCE_RE.finditer(chunk):
            results.append(
                NatInsideSourceRule(
                    device=_device_of(chunk),
                    acl_number=m.group(1),
                    interface=m.group(2),
                    pool_name=m.group(3),
                    overload=m.group(4) is not None,
                    source_line=m.group(0).strip(),
                )
            )
    return results


_STANDARD_ACL_CMD_RE = re.compile(r"Standard IP access list\s+(\S+)", re.IGNORECASE)
_ACL_PERMIT_RE = re.compile(
    r"permit\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)


def _wildcard_to_prefix(wildcard: str) -> int | None:
    """Convert a Cisco ACL wildcard mask (e.g. 0.0.0.255) to a prefix length."""
    try:
        octets = [int(o) for o in wildcard.split(".")]
        if len(octets) != 4 or any(o < 0 or o > 255 for o in octets):
            return None
        inverse = ".".join(str(255 - o) for o in octets)
        import ipaddress

        return ipaddress.IPv4Network(f"0.0.0.0/{inverse}", strict=False).prefixlen
    except ValueError:
        return None


def _parse_standard_acl_entries(chunks: list[str]) -> list[StandardAclEntry]:
    """Parse `show access-lists <n>` -> `Standard IP access list <n>` blocks."""
    results: list[StandardAclEntry] = []
    for chunk in chunks:
        cmd_m = _STANDARD_ACL_CMD_RE.search(chunk)
        if not cmd_m:
            continue
        permit_m = _ACL_PERMIT_RE.search(chunk)
        permitted_network = None
        if permit_m:
            prefix = _wildcard_to_prefix(permit_m.group(2))
            if prefix is not None:
                permitted_network = f"{permit_m.group(1)}/{prefix}"
        results.append(
            StandardAclEntry(
                acl_number=cmd_m.group(1),
                permitted_network=permitted_network,
                source_block=chunk.strip(),
            )
        )
    return results


_NAT_POOL_CMD_RE = re.compile(r"show ip nat pool\s+(\S+)", re.IGNORECASE)
_NAT_POOL_NETMASK_RE = re.compile(
    r"netmask\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)
_NAT_POOL_RANGE_RE = re.compile(
    r"start\s+(\d{1,3}(?:\.\d{1,3}){3})\s+end\s+(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)
_NAT_POOL_TOTAL_RE = re.compile(r"total addresses\s+(\d+)", re.IGNORECASE)
_NAT_POOL_ALLOCATED_RE = re.compile(r"allocated\s+(\d+)", re.IGNORECASE)


def _parse_nat_pools(chunks: list[str]) -> list[NatPoolInfo]:
    """Parse `show ip nat pool <name>` blocks (e.g. CASE_028)."""
    results: list[NatPoolInfo] = []
    for chunk in chunks:
        cmd_m = _NAT_POOL_CMD_RE.search(chunk)
        if not cmd_m:
            continue
        netmask_m = _NAT_POOL_NETMASK_RE.search(chunk)
        range_m = _NAT_POOL_RANGE_RE.search(chunk)
        total_m = _NAT_POOL_TOTAL_RE.search(chunk)
        alloc_m = _NAT_POOL_ALLOCATED_RE.search(chunk)
        results.append(
            NatPoolInfo(
                device=_device_of(chunk),
                pool_name=cmd_m.group(1),
                netmask=netmask_m.group(1) if netmask_m else None,
                start_ip=range_m.group(1) if range_m else None,
                end_ip=range_m.group(2) if range_m else None,
                total_addresses=int(total_m.group(1)) if total_m else None,
                allocated_addresses=int(alloc_m.group(1)) if alloc_m else None,
                source_block=chunk.strip(),
            )
        )
    return results


_STATED_LAN_SUBNET_RE = re.compile(
    r"subnet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})", re.IGNORECASE
)


def _parse_stated_lan_subnets(*texts: str) -> list[StatedLanSubnet]:
    """Parse statements like 'subnet 192.168.10.0/24' from symptom/topology text."""
    results: list[StatedLanSubnet] = []
    for text in texts:
        for m in _STATED_LAN_SUBNET_RE.finditer(text):
            results.append(
                StatedLanSubnet(network=f"{m.group(1)}/{m.group(2)}", source_line=m.group(0))
            )
    return results


_EXTENDED_ACL_CMD_RE = re.compile(r"Extended IP access list\s+(\S+)", re.IGNORECASE)
_ACL_LINE_RE = re.compile(r"^\s*(\d+)\s+(permit|deny)\s+(\S+)\s+(.+?)\s*$", re.IGNORECASE)
_ACL_MATCH_COUNT_RE = re.compile(r"\(\s*(\d+)\s*matches?\s*\)\s*$", re.IGNORECASE)
_IPV4_TOKEN_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _acl_consume_spec(tokens: list[str], idx: int) -> tuple[Optional[str], int]:
    """
    Consume one ACL source/destination specifier starting at tokens[idx].
    Returns (network_cidr_or_None, next_idx). Only 'any' and 'host <ip>'
    are treated as non-network specs; a bare '<ip> <wildcard>' pair is
    converted to a CIDR string via the existing wildcard-to-prefix helper.
    """
    if idx >= len(tokens):
        return None, idx
    if tokens[idx].lower() == "any":
        return None, idx + 1
    if tokens[idx].lower() == "host" and idx + 1 < len(tokens):
        return None, idx + 2
    if (
        idx + 1 < len(tokens)
        and _IPV4_TOKEN_RE.match(tokens[idx])
        and _IPV4_TOKEN_RE.match(tokens[idx + 1])
    ):
        prefix = _wildcard_to_prefix(tokens[idx + 1])
        cidr = f"{tokens[idx]}/{prefix}" if prefix is not None else None
        return cidr, idx + 2
    return None, idx + 1


def _parse_extended_acl_entries(chunks: list[str]) -> list[ExtendedAclEntry]:
    """Parse `show access-lists <name>` -> `Extended IP access list <name>` blocks."""
    results: list[ExtendedAclEntry] = []
    for chunk in chunks:
        cmd_m = _EXTENDED_ACL_CMD_RE.search(chunk)
        if not cmd_m:
            continue
        lines: list[ExtendedAclLine] = []
        for raw_line in chunk.splitlines():
            line_m = _ACL_LINE_RE.match(raw_line)
            if not line_m:
                continue
            seq_s, action, protocol, rest = line_m.groups()
            match_m = _ACL_MATCH_COUNT_RE.search(rest)
            match_count = int(match_m.group(1)) if match_m else None
            rest_clean = _ACL_MATCH_COUNT_RE.sub("", rest).strip()
            tokens = rest_clean.split()
            source_network, idx = _acl_consume_spec(tokens, 0)
            dest_network, _ = _acl_consume_spec(tokens, idx)
            lines.append(
                ExtendedAclLine(
                    sequence=int(seq_s),
                    action=action.lower(),
                    protocol=protocol.lower(),
                    rest=rest_clean,
                    match_count=match_count,
                    source_network=source_network,
                    dest_network=dest_network,
                    source_line=raw_line.strip(),
                )
            )
        results.append(
            ExtendedAclEntry(acl_name=cmd_m.group(1), lines=lines, source_block=chunk.strip())
        )
    return results


_SHOW_IP_INTERFACE_CMD_RE = re.compile(r"show ip interface\s+(\S+)(?!\s+brief)", re.IGNORECASE)
_ACL_INBOUND_RE = re.compile(r"Inbound\s+access\s+list\s+is\s+(not set|\S+)", re.IGNORECASE)
_ACL_OUTBOUND_RE = re.compile(r"Outbound\s+access\s+list\s+is\s+(not set|\S+)", re.IGNORECASE)


def _acl_or_none(m: "re.Match | None") -> str | None:
    if not m:
        return None
    val = m.group(1)
    return None if val.lower() == "not set" else val


def _parse_acl_interface_bindings(chunks: list[str]) -> list[AclInterfaceBinding]:
    """Parse `show ip interface <if>` Inbound/Outbound access-list lines."""
    results: list[AclInterfaceBinding] = []
    for chunk in chunks:
        if "brief" in chunk.lower():
            continue
        cmd_m = _SHOW_IP_INTERFACE_CMD_RE.search(chunk)
        if not cmd_m:
            continue
        in_m = _ACL_INBOUND_RE.search(chunk)
        out_m = _ACL_OUTBOUND_RE.search(chunk)
        if not (in_m or out_m):
            continue
        results.append(
            AclInterfaceBinding(
                device=_device_of(chunk),
                interface=cmd_m.group(1),
                inbound_acl=_acl_or_none(in_m),
                outbound_acl=_acl_or_none(out_m),
                source_block=chunk.strip(),
            )
        )
    return results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_case(case: NetworkCase) -> ParsedEvidence:
    """Extract all normalized evidence from a single NetworkCase."""
    chunks = _split_paragraphs(case.show_outputs)

    ip_configs = _parse_ipconfig_blocks(chunks) + _parse_show_ip_interface_single(chunks)
    interface_briefs = _parse_interface_brief(chunks)
    vlan_entries = _parse_vlan_brief(chunks)
    switchport_infos = _parse_switchport_blocks(chunks)
    trunk_infos = _parse_trunk_blocks(chunks)
    intended_vlan_bindings = _parse_intended_vlan_bindings(case.topology_note)
    running_config_vlan_assignments = _parse_running_config_vlan_assignments(chunks)
    mentioned_vlans = _parse_mentioned_vlans(case.symptom, case.topology_note)
    stated_subnets = _parse_stated_subnets(case.topology_note)
    route_entries, routed_devices = _parse_route_tables(_split_by_device_prompt(case.show_outputs))
    lan_bindings = _parse_lan_bindings(case.topology_note)

    device_segments = _split_by_device_prompt(case.show_outputs)
    dhcp_pool_stats = _parse_dhcp_pool_stats(device_segments)
    dhcp_pool_configs = _parse_dhcp_pool_configs(device_segments)
    dhcp_bindings = _parse_dhcp_bindings(device_segments)
    dhcp_interface_configs = _parse_dhcp_interface_configs(device_segments)
    stated_dhcp_servers = _parse_stated_dhcp_servers(case.topology_note)
    dhcp_service_enabled = _parse_dhcp_service_enabled(case.show_outputs)

    nat_statistics = _parse_nat_statistics(chunks)
    nat_inside_source_rules = _parse_nat_inside_source_rules(chunks)
    standard_acl_entries = _parse_standard_acl_entries(chunks)
    nat_pools = _parse_nat_pools(chunks)
    stated_lan_subnets = _parse_stated_lan_subnets(case.symptom, case.topology_note)

    extended_acl_entries = _parse_extended_acl_entries(chunks)
    acl_interface_bindings = _parse_acl_interface_bindings(chunks)

    return ParsedEvidence(
        ip_configs=ip_configs,
        interface_briefs=interface_briefs,
        vlan_entries=vlan_entries,
        switchport_infos=switchport_infos,
        trunk_infos=trunk_infos,
        intended_vlan_bindings=intended_vlan_bindings,
        running_config_vlan_assignments=running_config_vlan_assignments,
        mentioned_vlans=mentioned_vlans,
        stated_subnets=stated_subnets,
        route_entries=route_entries,
        routed_devices=routed_devices,
        lan_bindings=lan_bindings,
        dhcp_pool_stats=dhcp_pool_stats,
        dhcp_pool_configs=dhcp_pool_configs,
        dhcp_bindings=dhcp_bindings,
        dhcp_interface_configs=dhcp_interface_configs,
        stated_dhcp_servers=stated_dhcp_servers,
        dhcp_service_enabled=dhcp_service_enabled,
        nat_statistics=nat_statistics,
        nat_inside_source_rules=nat_inside_source_rules,
        standard_acl_entries=standard_acl_entries,
        nat_pools=nat_pools,
        stated_lan_subnets=stated_lan_subnets,
        extended_acl_entries=extended_acl_entries,
        acl_interface_bindings=acl_interface_bindings,
    )
