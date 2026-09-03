"""
models.py
---------
Structured data models for the NetSage AI Rule-Based Troubleshooting Engine.

Three groups of models live here:

1. NetworkCase        - the raw case exactly as it exists in data/cases.csv
2. Parsed-evidence     - normalized structures produced by evidence_analyzer.py
   (HostIPConfig, VlanBriefEntry, SwitchportInfo, TrunkInfo,
   InterfaceBriefEntry, IntendedVlanBinding, RunningConfigVlanAssignment,
   RouteTableEntry, LanBinding, and the Dhcp* models below) from the messy
   free-text `show_outputs` / `topology_note` fields, all bundled into
   ParsedEvidence.
3. RuleFinding / RuleResult - the structured output the engine produces.

IMPORTANT: The task brief assumed a richer schema (title, issue_category,
security_relevance, security_impact, expected_next_command, ground_truth).
The real dataset (data/cases.csv) has only 9 columns:
case_id, symptom, topology_note, show_outputs, expected_fault, osi_layer,
concept_tag, severity, fix_steps.
NetworkCase below models the REAL schema, not the assumed one. See
DATASET_ASSESSMENT.md for the full discussion of this mismatch.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# 1. Raw case model
# ---------------------------------------------------------------------------


class NetworkCase(BaseModel):
    """One row of data/cases.csv, matching the dataset's real columns."""

    case_id: str
    symptom: str
    topology_note: str
    show_outputs: str
    expected_fault: str
    osi_layer: str
    concept_tag: str
    severity: str
    fix_steps: str

    @field_validator("case_id")
    @classmethod
    def case_id_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("case_id must not be empty")
        return v.strip()


# ---------------------------------------------------------------------------
# 2. Parsed-evidence models (output of evidence_analyzer.py)
# ---------------------------------------------------------------------------


class HostIPConfig(BaseModel):
    """
    A single IP-addressing fact found in the text: either a PC `ipconfig`
    block, or a router `show ip interface <name>` block ('Internet address
    is X/Y'). Any field may be None if that piece wasn't present.
    """

    source_line: str
    device: Optional[str] = None
    interface: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    prefix_len: Optional[int] = None
    default_gateway: Optional[str] = None


class InterfaceBriefEntry(BaseModel):
    """One row of a `show ip interface brief` table."""

    interface: str
    ip_address: str
    status: str
    protocol: str
    source_line: str


class VlanBriefEntry(BaseModel):
    """One row of a `show vlan brief` table."""

    vlan_id: int
    name: str
    status: str
    ports: list[str] = []
    source_line: str


class SwitchportInfo(BaseModel):
    """Parsed `show interfaces <if> switchport` block."""

    device: Optional[str] = None
    interface: Optional[str] = None
    administrative_mode: Optional[str] = None
    operational_mode: Optional[str] = None
    access_vlan: Optional[int] = None
    administrative_native_vlan: Optional[int] = None
    operational_native_vlan: Optional[int] = None
    source_block: str


class TrunkInfo(BaseModel):
    """Parsed `show interfaces trunk` block."""

    device: Optional[str] = None
    port: Optional[str] = None
    native_vlan: Optional[int] = None
    allowed_vlans: list[int] = []
    source_block: str


class RouteTableEntry(BaseModel):
    """One route-table row parsed from `show ip route` / `show ip route static`."""

    device: Optional[str] = None
    network: str  # CIDR string, e.g. "192.168.20.0/24"
    code: str  # e.g. "C", "S", "R"
    next_hop: Optional[str] = None
    source_line: str


class LanBinding(BaseModel):
    """A statement like 'R2 LAN: 172.16.30.0/24' or 'R1 LAN 192.168.10.0/24'."""

    router: str
    network: str  # CIDR string
    source_line: str


class IntendedVlanBinding(BaseModel):
    """A statement like 'PC-1 on Fa0/1 (intended VLAN 20)' from topology_note."""

    port: str
    intended_vlan: int
    source_line: str


class RunningConfigVlanAssignment(BaseModel):
    """A `switchport access vlan N` line found inside a running-config excerpt."""

    interface: Optional[str] = None
    vlan_id: int
    source_line: str


# --- DHCP evidence models --------------------------------------------------


class DhcpPoolStats(BaseModel):
    """Parsed `show ip dhcp pool <name>` utilization block (e.g. CASE_010)."""

    device: Optional[str] = None
    pool_name: Optional[str] = None
    total_addresses: Optional[int] = None
    leased_addresses: Optional[int] = None
    source_block: str


class DhcpPoolConfig(BaseModel):
    """
    An `ip dhcp pool <name>` configuration block parsed from a running-config
    excerpt (e.g. CASE_012, CASE_013): network + default-router lines.
    """

    device: Optional[str] = None
    pool_name: Optional[str] = None
    network: Optional[str] = None  # e.g. "192.168.1.0 255.255.255.0"
    default_router: Optional[str] = None
    source_block: str


class DhcpBindingEntry(BaseModel):
    """One row of a `show ip dhcp binding` table."""

    device: Optional[str] = None
    ip_address: str
    client_id: Optional[str] = None
    source_line: str


class DhcpInterfaceConfig(BaseModel):
    """A `show running-config interface <if>` block, for DHCP-relay checks."""

    device: Optional[str] = None
    interface: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    helper_addresses: list[str] = []
    source_block: str


class StatedDhcpServer(BaseModel):
    """A DHCP server IP mentioned in topology_note (e.g. 'DHCP Server 10.0.2.100')."""

    ip_address: str
    source_line: str


# --- NAT evidence models ---------------------------------------------------


class NatStatistics(BaseModel):
    """Parsed `show ip nat statistics` block."""

    device: Optional[str] = None
    total_active_translations: Optional[int] = None
    outside_interfaces: list[str] = []
    inside_interfaces: list[str] = []
    # True if the literal "none configured" text appeared under that section.
    outside_none_configured: bool = False
    inside_none_configured: bool = False
    source_block: str


class NatInsideSourceRule(BaseModel):
    """A `ip nat inside source list <acl> [interface <if> | pool <name>] [overload]` line."""

    device: Optional[str] = None
    acl_number: Optional[str] = None
    interface: Optional[str] = None
    pool_name: Optional[str] = None
    overload: bool = False
    source_line: str


class StandardAclEntry(BaseModel):
    """A `Standard IP access list <n>` block with its `permit <net> <wildcard>` line."""

    acl_number: str
    permitted_network: Optional[str] = None  # CIDR string, e.g. "192.168.1.0/24"
    source_block: str


class NatPoolInfo(BaseModel):
    """Parsed `show ip nat pool <name>` block."""

    device: Optional[str] = None
    pool_name: Optional[str] = None
    netmask: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    total_addresses: Optional[int] = None
    allocated_addresses: Optional[int] = None
    source_block: str


class StatedLanSubnet(BaseModel):
    """A statement like 'subnet 192.168.10.0/24' found in symptom/topology text."""

    network: str  # CIDR string
    source_line: str


# --- Extended ACL evidence models ------------------------------------------


class ExtendedAclLine(BaseModel):
    """One numbered line inside an `Extended IP access list <name>` block."""

    sequence: Optional[int] = None
    action: str  # "permit" or "deny"
    protocol: str  # e.g. "tcp", "ip", "icmp"
    rest: str  # everything after the protocol keyword, match-count suffix stripped
    match_count: Optional[int] = None
    # Populated only when that side of the line is expressed as
    # `<network> <wildcard-mask>` (not "any" or "host <ip>").
    source_network: Optional[str] = None  # CIDR string
    dest_network: Optional[str] = None  # CIDR string
    source_line: str


class ExtendedAclEntry(BaseModel):
    """A full `show access-lists <name>` -> `Extended IP access list <name>` block."""

    acl_name: str
    lines: list[ExtendedAclLine] = []
    source_block: str


class AclInterfaceBinding(BaseModel):
    """
    Parsed `show ip interface <if>` Inbound/Outbound access-list lines
    (e.g. 'Inbound access list is 101', 'Outbound access list is not set').
    """

    device: Optional[str] = None
    interface: Optional[str] = None
    inbound_acl: Optional[str] = None  # None means "not set"
    outbound_acl: Optional[str] = None  # None means "not set"
    source_block: str


class ParsedEvidence(BaseModel):
    """All normalized evidence extracted from one NetworkCase."""

    ip_configs: list[HostIPConfig] = []
    interface_briefs: list[InterfaceBriefEntry] = []
    vlan_entries: list[VlanBriefEntry] = []
    switchport_infos: list[SwitchportInfo] = []
    trunk_infos: list[TrunkInfo] = []
    intended_vlan_bindings: list[IntendedVlanBinding] = []
    running_config_vlan_assignments: list[RunningConfigVlanAssignment] = []
    mentioned_vlans: list[int] = []
    stated_subnets: list[str] = []
    route_entries: list[RouteTableEntry] = []
    routed_devices: list[str] = []  # devices that issued a `show ip route[...]` command
    lan_bindings: list[LanBinding] = []
    dhcp_pool_stats: list[DhcpPoolStats] = []
    dhcp_pool_configs: list[DhcpPoolConfig] = []
    dhcp_bindings: list[DhcpBindingEntry] = []
    dhcp_interface_configs: list[DhcpInterfaceConfig] = []
    stated_dhcp_servers: list[StatedDhcpServer] = []
    # True = "service dhcp" explicitly confirmed enabled, False = "no service
    # dhcp" found (disabled), None = not mentioned either way.
    dhcp_service_enabled: Optional[bool] = None
    nat_statistics: list[NatStatistics] = []
    nat_inside_source_rules: list[NatInsideSourceRule] = []
    standard_acl_entries: list[StandardAclEntry] = []
    nat_pools: list[NatPoolInfo] = []
    stated_lan_subnets: list[StatedLanSubnet] = []
    extended_acl_entries: list[ExtendedAclEntry] = []
    acl_interface_bindings: list[AclInterfaceBinding] = []


# ---------------------------------------------------------------------------
# 3. Rule output models
# ---------------------------------------------------------------------------


class RuleStatus(str, Enum):
    """The only three statuses a rule is allowed to report."""

    PASS = "PASS"
    FAILED = "FAILED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class RuleFinding(BaseModel):
    """The structured result of running exactly one rule on one case."""

    rule_id: str
    rule_name: str
    category: str
    status: RuleStatus
    finding: str
    evidence: list[str] = []
    severity: Optional[str] = None
    recommended_next_command: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class RuleResult(BaseModel):
    """All findings produced by the engine for a single case."""

    case_id: str
    rule_findings: list[RuleFinding] = []

    def to_dict(self) -> dict:
        return self.model_dump()
