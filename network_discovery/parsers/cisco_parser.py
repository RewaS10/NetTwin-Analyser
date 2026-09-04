from __future__ import annotations

import re
from pathlib import Path

from network_discovery.device_detector import detect_device_type
from network_discovery.models import NetworkDevice, NetworkInterface
from network_discovery.parsers.neighbor_parser import parse_neighbors

def parse_cisco_config(
    config_text: str,
    source_file: str | None = None,
) -> NetworkDevice:
    """
    Parse a basic Cisco-style configuration file and return
    a discovered NetworkDevice.
    """

    hostname = _extract_hostname(config_text)

    device_type = detect_device_type(config_text)

    device = NetworkDevice(
        hostname=hostname,
        device_type=device_type,
        source_file=source_file,
    )

    device.interfaces = _extract_interfaces(config_text)
    device.vlans = _extract_vlans(config_text)
    device.routing_protocols = _extract_routing_protocols(config_text)
    device.neighbors = parse_neighbors(config_text)

    return device


def parse_cisco_file(file_path: str | Path) -> NetworkDevice:
    """Read and parse a Cisco-style configuration file."""

    path = Path(file_path)

    config_text = path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    return parse_cisco_config(
        config_text,
        source_file=path.name,
    )


def _extract_hostname(config_text: str) -> str:
    """Extract the hostname from a Cisco configuration."""

    match = re.search(
        r"(?im)^\s*hostname\s+(\S+)",
        config_text,
    )

    if match:
        return match.group(1)

    return "Unknown_Device"


def _extract_interfaces(
    config_text: str,
) -> list[NetworkInterface]:
    """Extract interface blocks and their basic properties."""

    interfaces = []

    pattern = re.compile(
        r"(?ims)^interface\s+(\S+)(.*?)(?=^interface\s+|\Z)"
    )

    for match in pattern.finditer(config_text):

        interface_name = match.group(1)
        interface_block = match.group(2)

        ip_address = None
        subnet_mask = None
        status = "up"
        vlan = None
        description = None

        ip_match = re.search(
            r"(?im)^\s*ip address\s+(\S+)\s+(\S+)",
            interface_block,
        )

        if ip_match:
            ip_address = ip_match.group(1)
            subnet_mask = ip_match.group(2)

        if re.search(
            r"(?im)^\s*shutdown\s*$",
            interface_block,
        ):
            status = "down"

        if re.search(
            r"(?im)^\s*no shutdown\s*$",
            interface_block,
        ):
            status = "up"

        vlan_match = re.search(
            r"(?im)^\s*switchport access vlan\s+(\d+)",
            interface_block,
        )

        if vlan_match:
            vlan = vlan_match.group(1)

        description_match = re.search(
            r"(?im)^\s*description\s+(.+)$",
            interface_block,
        )

        if description_match:
            description = description_match.group(1).strip()

        interfaces.append(
            NetworkInterface(
                name=interface_name,
                ip_address=ip_address,
                subnet_mask=subnet_mask,
                status=status,
                vlan=vlan,
                description=description,
            )
        )

    return interfaces


def _extract_vlans(config_text: str) -> list[str]:
    """Extract VLAN IDs from Cisco configuration."""

    vlans = re.findall(
        r"(?im)^\s*vlan\s+(\d+)",
        config_text,
    )

    return sorted(set(vlans), key=int)


def _extract_routing_protocols(
    config_text: str,
) -> list[str]:
    """Detect configured routing protocols."""

    protocols = []

    if re.search(
        r"(?im)^\s*router\s+ospf\b",
        config_text,
    ):
        protocols.append("OSPF")

    if re.search(
        r"(?im)^\s*router\s+eigrp\b",
        config_text,
    ):
        protocols.append("EIGRP")

    if re.search(
        r"(?im)^\s*router\s+bgp\b",
        config_text,
    ):
        protocols.append("BGP")

    if re.search(
        r"(?im)^\s*rip\b",
        config_text,
    ):
        protocols.append("RIP")

    return protocols