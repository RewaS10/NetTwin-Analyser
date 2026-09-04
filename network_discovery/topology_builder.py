from __future__ import annotations

import ipaddress
import re

from network_discovery.models import NetworkDevice, NetworkTopology


def build_topology(devices: list[NetworkDevice]) -> NetworkTopology:
    """
    Build a network topology using multiple sources of evidence.

    Connection confidence priority:
    1. CDP / LLDP neighbor discovery
    2. Interface descriptions
    3. Shared IP subnets
    """
    topology = NetworkTopology()

    for device in devices:
        topology.add_device(device)

    _infer_neighbor_connections(devices, topology)
    _infer_description_connections(devices, topology)
    _infer_subnet_connections(devices, topology)

    return topology


def _infer_neighbor_connections(
    devices: list[NetworkDevice],
    topology: NetworkTopology,
) -> None:
    """Infer direct connections from CDP/LLDP neighbor information."""

    hostnames = {
        device.hostname.lower(): device.hostname
        for device in devices
    }

    for device in devices:
        for neighbor in device.neighbors:

            neighbor_hostname = hostnames.get(neighbor.lower())

            if not neighbor_hostname:
                continue

            topology.add_connection(
                device.hostname,
                neighbor_hostname,
                evidence="CDP/LLDP Neighbor Discovery",
                confidence="High",
            )


def _infer_description_connections(
    devices: list[NetworkDevice],
    topology: NetworkTopology,
) -> None:
    """Infer connections from interface descriptions."""

    hostnames = {
        device.hostname.lower(): device.hostname
        for device in devices
    }

    for device in devices:
        for interface in device.interfaces:

            if not interface.description:
                continue

            description = interface.description.lower()

            for hostname_lower, hostname in hostnames.items():

                if hostname == device.hostname:
                    continue

                pattern = (
                    r"(?<![a-zA-Z0-9])"
                    + re.escape(hostname_lower)
                    + r"(?![a-zA-Z0-9])"
                )

                if re.search(pattern, description):

                    topology.add_connection(
                        device.hostname,
                        hostname,
                        evidence="Interface Description",
                        confidence="Medium",
                    )


def _infer_subnet_connections(
    devices: list[NetworkDevice],
    topology: NetworkTopology,
) -> None:
    """Infer possible connections from interfaces sharing the same subnet."""

    subnet_members: dict[str, set[str]] = {}

    for device in devices:

        for interface in device.interfaces:

            if not (
                interface.ip_address
                and interface.subnet_mask
            ):
                continue

            try:
                network = ipaddress.ip_network(
                    f"{interface.ip_address}/{interface.subnet_mask}",
                    strict=False,
                )

            except ValueError:
                continue

            subnet_members.setdefault(
                str(network),
                set(),
            ).add(device.hostname)

    for network, members in subnet_members.items():

        if len(members) < 2:
            continue

        sorted_members = sorted(members)

        for index, device_a in enumerate(sorted_members):

            for device_b in sorted_members[index + 1:]:

                topology.add_connection(
                    device_a,
                    device_b,
                    evidence=f"Shared Subnet: {network}",
                    confidence="Low",
                )