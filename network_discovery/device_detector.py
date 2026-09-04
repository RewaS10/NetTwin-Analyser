from __future__ import annotations

DEVICE_TYPE_KEYWORDS: dict[str, list[str]] = {
    "Firewall": [
        "firewall",
        "firepower",
        "asa",
        "security-level",
        "access-group",
        "nat ",
        "object network",
        "policy-map",
    ],
    "Switch": [
        "switchport",
        "switchport mode access",
        "switchport mode trunk",
        "spanning-tree",
        "vlan ",
        "interface vlan",
    ],
    "Router": [
        "router ospf",
        "router eigrp",
        "router bgp",
        "ip route",
        "ipv6 route",
        "ip routing",
    ],
}


def _score_device_types(text: str) -> dict[str, list[str]]:
    """Return matched keywords per device type for the given lowercased text."""
    return {
        device_type: [kw for kw in keywords if kw in text]
        for device_type, keywords in DEVICE_TYPE_KEYWORDS.items()
    }


def detect_device_type(config_text: str) -> str:
    """
    Detect the likely network device type from configuration content.
    Currently supports basic Cisco-style configuration detection.
    """
    matches = _score_device_types(config_text.lower())
    device_type, best_matches = max(matches.items(), key=lambda item: len(item[1]))
    return device_type if best_matches else "Unknown"


def get_detection_details(config_text: str) -> dict[str, dict[str, object]]:
    """
    Return detection scores and matched keywords for debugging and UI display.
    """
    matches = _score_device_types(config_text.lower())
    return {
        device_type: {"score": len(matched), "matches": matched}
        for device_type, matched in matches.items()
    }