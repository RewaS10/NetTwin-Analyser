from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetworkInterface:
    """Represents a network interface discovered from a device configuration."""

    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    status: str = "unknown"
    vlan: Optional[str] = None
    description: Optional[str] = None

    @property
    def is_up(self) -> bool:
        """True if the interface status indicates it is operational."""
        return self.status.lower() in {"up", "active", "connected"}

    def __str__(self) -> str:
        addr = f" ({self.ip_address})" if self.ip_address else ""
        return f"{self.name}{addr} [{self.status}]"
@dataclass
class NetworkConnection:
    """Represents a discovered connection and the evidence supporting it."""

    device_a: str
    device_b: str
    confidence: str = "Low"
    evidence: list[str] = field(default_factory=list)

    def add_evidence(
        self,
        source: str,
        confidence: str | None = None,
    ) -> None:
        """Add evidence for this connection without duplicating it."""

        if source not in self.evidence:
            self.evidence.append(source)

        confidence_rank = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
        }

        if confidence is not None:
            current_rank = confidence_rank.get(self.confidence, 1)
            new_rank = confidence_rank.get(confidence, 1)

            if new_rank > current_rank:
                self.confidence = confidence

    @property
    def key(self) -> tuple[str, str]:
        """Return a consistent order-independent connection key."""

        return tuple(sorted((self.device_a, self.device_b)))

@dataclass
class NetworkDevice:
    """Represents a network device discovered from an uploaded file."""

    hostname: str
    device_type: str = "Unknown"

    interfaces: list[NetworkInterface] = field(default_factory=list)
    vlans: list[str] = field(default_factory=list)
    routing_protocols: list[str] = field(default_factory=list)
    neighbors: list[str] = field(default_factory=list)
    source_file: Optional[str] = None
    def add_interface(self, interface: NetworkInterface) -> None:
        """Add an interface to this device."""
        self.interfaces.append(interface)

    def get_interface(self, name: str) -> Optional[NetworkInterface]:
        """Look up an interface by name, or None if not found."""
        return next(
            (
                interface
                for interface in self.interfaces
                if interface.name == name
            ),
            None,
        )

    @property
    def active_interfaces(self) -> list[NetworkInterface]:
        """Return interfaces currently considered operational."""
        return [
            interface
            for interface in self.interfaces
            if interface.is_up
        ]

    def __str__(self) -> str:
        return (
            f"{self.hostname} "
            f"({self.device_type}, {len(self.interfaces)} interfaces)"
        )


@dataclass
class NetworkTopology:
    """Represents the discovered network topology."""

    devices: list[NetworkDevice] = field(default_factory=list)
    connections: list[NetworkConnection] = field(default_factory=list)

    def add_device(self, device: NetworkDevice) -> None:
        """Add a device to the topology."""
        self.devices.append(device)

    def get_device(self, hostname: str) -> Optional[NetworkDevice]:
        """Look up a device by hostname, or None if not found."""
        return next(
            (
                device
                for device in self.devices
                if device.hostname == hostname
            ),
            None,
        )

    def add_connection(
        self,
        hostname_a: str,
        hostname_b: str,
        evidence: str = "Unknown",
        confidence: str = "Low",
    ) -> None:
        """Add or update a discovered connection."""

        if hostname_a == hostname_b:
            return

        connection_key = tuple(sorted((hostname_a, hostname_b)))

        for connection in self.connections:
            if connection.key == connection_key:
                connection.add_evidence(evidence, confidence)
                return

        connection = NetworkConnection(
            device_a=hostname_a,
            device_b=hostname_b,
            confidence=confidence,
            evidence=[evidence],
        )

        self.connections.append(connection)

    @property
    def device_count(self) -> int:
        """Return the number of discovered devices."""
        return len(self.devices)

    def __str__(self) -> str:
        return (
            f"NetworkTopology("
            f"{self.device_count} devices, "
            f"{len(self.connections)} connections)"
        )

