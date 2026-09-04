from __future__ import annotations

import re


def parse_cdp_neighbors(config_text: str) -> list[str]:
    """
    Extract neighbor device hostnames from Cisco CDP output.

    Supports common formats such as:

    Device ID: R2
    Interface: GigabitEthernet0/1

    and simple CDP neighbor tables.
    """

    neighbors: list[str] = []

    # Detailed Cisco CDP output:
    # Device ID: R2
    device_id_pattern = re.compile(
        r"Device\s+ID\s*:\s*([^\s,]+)",
        re.IGNORECASE,
    )

    for match in device_id_pattern.finditer(config_text):
        hostname = match.group(1).strip()

        if hostname and hostname not in neighbors:
            neighbors.append(hostname)

    return neighbors


def parse_lldp_neighbors(config_text: str) -> list[str]:
    """
    Extract neighbor device names from LLDP output.

    Supports common Cisco-style formats such as:

    System Name: SW1
    """

    neighbors: list[str] = []

    system_name_pattern = re.compile(
        r"System\s+Name\s*:\s*([^\s,]+)",
        re.IGNORECASE,
    )

    for match in system_name_pattern.finditer(config_text):
        hostname = match.group(1).strip()

        if hostname and hostname not in neighbors:
            neighbors.append(hostname)

    return neighbors


def parse_neighbors(config_text: str) -> list[str]:
    """
    Extract all unique CDP and LLDP neighbors.
    """

    neighbors: list[str] = []

    for hostname in parse_cdp_neighbors(config_text):
        if hostname not in neighbors:
            neighbors.append(hostname)

    for hostname in parse_lldp_neighbors(config_text):
        if hostname not in neighbors:
            neighbors.append(hostname)

    return neighbors