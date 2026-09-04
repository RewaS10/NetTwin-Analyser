from __future__ import annotations

import math

import plotly.graph_objects as go
import streamlit as st

# Single source of truth for per-device-type styling: symbol, marker size, color.
DEVICE_STYLES: dict[str, dict[str, object]] = {
    "Firewall": {"symbol": "diamond", "size": 42, "color": "#F97316"},
    "Router": {"symbol": "circle", "size": 38, "color": "#38BDF8"},
    "Switch": {"symbol": "square", "size": 38, "color": "#22C55E"},
    "Unknown": {"symbol": "circle", "size": 32, "color": "#94A3B8"},
}

# Network hierarchy, top to bottom: perimeter -> distribution -> access.
# Any device type not listed here (including "Unknown") falls into the bottom tier.
TIER_ORDER: list[str] = ["Firewall", "Router", "Switch"]
OTHER_TIER_LABEL = "Devices"

EDGE_COLOR = "#4C78A8"
EDGE_WIDTH = 2
MARKER_BORDER_COLOR = "#FFFFFF"
MARKER_BORDER_WIDTH = 2
CHART_HEIGHT = 600
CHART_BACKGROUND = "#0E1117"
FONT_COLOR = "#D6D6D6"
TIER_LINE_COLOR = "#2A2E39"
TIER_LABEL_COLOR = "#6B7280"

TIER_VERTICAL_SPACING = 6.0
MIN_HORIZONTAL_SPACING = 5.0


def render_topology(topology) -> None:
    """Render an interactive, hierarchy-aware visualization of a network topology."""
    if not topology.devices:
        st.info("No devices available to visualize.")
        return

    tiers = _group_devices_by_tier(topology.devices)
    adjacency = _build_adjacency(topology.connections)
    positions = _calculate_hierarchical_positions(tiers, adjacency)

    fig = go.Figure()
    _add_tier_guides(fig, tiers, positions)
    _add_connection_traces(fig, topology, positions)
    _add_device_traces(fig, tiers, positions)
    _apply_layout(fig)

    st.plotly_chart(fig, use_container_width=True, key="dynamic_topology_chart")


def _group_devices_by_tier(devices: list) -> list[tuple[str, list]]:
    """
    Group devices into hierarchy tiers, top to bottom.

    Returns a list of (tier_label, devices) pairs, in display order, omitting
    any tier that has no devices.
    """
    tier_labels = TIER_ORDER + [OTHER_TIER_LABEL]
    buckets: dict[str, list] = {label: [] for label in tier_labels}

    for device in devices:
        label = device.device_type if device.device_type in TIER_ORDER else OTHER_TIER_LABEL
        buckets[label].append(device)

    return [(label, devices) for label, devices in buckets.items() if devices]


def _build_adjacency(connections) -> dict[str, set[str]]:
    """Build an undirected hostname -> connected-hostnames lookup."""

    adjacency: dict[str, set[str]] = {}

    for connection in connections:
        device_a = connection.device_a
        device_b = connection.device_b

        adjacency.setdefault(device_a, set()).add(device_b)
        adjacency.setdefault(device_b, set()).add(device_a)

    return adjacency

def _calculate_hierarchical_positions(
    tiers: list[tuple[str, list]],
    adjacency: dict[str, set[str]],
) -> dict[str, tuple[float, float]]:
    """
    Position devices in horizontal layers, ordered top to bottom by TIER_ORDER.

    Within each tier (after the first), devices are ordered by the average
    x-position of their connections in the tier above (a barycenter heuristic)
    to reduce line crossings between layers.
    """
    positions: dict[str, tuple[float, float]] = {}
    total_tiers = len(tiers)

    for tier_index, (_, devices) in enumerate(tiers):
        y = (total_tiers - 1 - tier_index) * TIER_VERTICAL_SPACING

        if tier_index == 0:
            ordered_devices = devices
        else:
            ordered_devices = _order_by_barycenter(devices, adjacency, positions)

        count = len(ordered_devices)
        for slot, device in enumerate(ordered_devices):
            x = (slot - (count - 1) / 2) * MIN_HORIZONTAL_SPACING
            positions[device.hostname] = (x, y)

    return positions


def _order_by_barycenter(
    devices: list,
    adjacency: dict[str, set[str]],
    placed_positions: dict[str, tuple[float, float]],
) -> list:
    """
    Order devices by the average x-position of already-placed connections.

    Devices with no connections to previously placed tiers are pushed to the
    end, in their original relative order (stable sort).
    """
    def barycenter(device) -> float:
        connected_x = [
            placed_positions[host][0]
            for host in adjacency.get(device.hostname, ())
            if host in placed_positions
        ]
        return sum(connected_x) / len(connected_x) if connected_x else math.inf

    return sorted(devices, key=barycenter)


def _add_tier_guides(
    fig: go.Figure,
    tiers: list[tuple[str, list]],
    positions: dict[str, tuple[float, float]],
) -> None:
    """Draw a faint horizontal guide line and label for each hierarchy tier."""
    if not positions:
        return

    all_x = [x for x, _ in positions.values()]
    left, right = min(all_x) - MIN_HORIZONTAL_SPACING, max(all_x) + MIN_HORIZONTAL_SPACING

    seen_y: set[float] = set()
    for label, devices in tiers:
        y = positions[devices[0].hostname][1]
        if y in seen_y:
            continue
        seen_y.add(y)

        fig.add_shape(
            type="line",
            x0=left,
            x1=right,
            y0=y,
            y1=y,
            line=dict(color=TIER_LINE_COLOR, width=1, dash="dot"),
            layer="below",
        )
        fig.add_annotation(
            x=left,
            y=y,
            text=label.upper(),
            showarrow=False,
            xanchor="right",
            font=dict(color=TIER_LABEL_COLOR, size=11),
        )


def _add_connection_traces(
    fig: go.Figure,
    topology,
    positions: dict[str, tuple[float, float]],
) -> None:
    """
    Draw network connections.

    Connections are styled according to their confidence level.
    """

    confidence_styles = {
        "High": {
            "dash": "solid",
            "width": 3,
        },
        "Medium": {
            "dash": "dash",
            "width": 2,
        },
        "Low": {
            "dash": "dot",
            "width": 1,
        },
    }

    for connection in topology.connections:

        device_a = connection.device_a
        device_b = connection.device_b

        if device_a not in positions or device_b not in positions:
            continue

        x1, y1 = positions[device_a]
        x2, y2 = positions[device_b]

        style = confidence_styles.get(
            connection.confidence,
            confidence_styles["Low"],
        )

        evidence_text = "<br>".join(connection.evidence)

        hover_text = (
            f"<b>{device_a} ↔ {device_b}</b><br>"
            f"Confidence: {connection.confidence}<br>"
            f"Evidence:<br>{evidence_text}"
        )

        fig.add_trace(
            go.Scatter(
                x=[x1, x2],
                y=[y1, y2],
                mode="lines",
                line=dict(
                    width=style["width"],
                    dash=style["dash"],
                    color=EDGE_COLOR,
                ),
                hovertext=hover_text,
                hoverinfo="text",
                showlegend=False,
            )
        )


def _add_device_traces(
    fig: go.Figure,
    tiers: list[tuple[str, list]],
    positions: dict[str, tuple[float, float]],
) -> None:
    """Draw one marker trace per device type, added in hierarchy order for a clean legend."""
    for _, devices in tiers:
        devices_by_type: dict[str, list] = {}
        for device in devices:
            devices_by_type.setdefault(device.device_type, []).append(device)

        for device_type, type_devices in devices_by_type.items():
            style = DEVICE_STYLES.get(device_type, DEVICE_STYLES["Unknown"])

            x_values = [positions[d.hostname][0] for d in type_devices]
            y_values = [positions[d.hostname][1] for d in type_devices]
            labels = [d.hostname for d in type_devices]
            hover_text = [_build_hover_text(d) for d in type_devices]

            fig.add_trace(
                go.Scatter(
                    x=x_values,
                    y=y_values,
                    mode="markers+text",
                    text=labels,
                    textposition="bottom center",
                    hovertext=hover_text,
                    hoverinfo="text",
                    marker=dict(
                        symbol=style["symbol"],
                        size=style["size"],
                        color=style["color"],
                        line=dict(width=MARKER_BORDER_WIDTH, color=MARKER_BORDER_COLOR),
                    ),
                    name=device_type,
                )
            )


def _apply_layout(fig: go.Figure) -> None:
    """Apply shared chart styling: dark theme, hidden axes, centered legend."""
    fig.update_layout(
        height=CHART_HEIGHT,
        paper_bgcolor=CHART_BACKGROUND,
        plot_bgcolor=CHART_BACKGROUND,
        font=dict(color=FONT_COLOR),
        margin=dict(l=90, r=20, t=40, b=20),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        hovermode="closest",
    )
    fig.update_xaxes(visible=False, showgrid=False, zeroline=False)
    fig.update_yaxes(visible=False, showgrid=False, zeroline=False)


def _build_hover_text(device) -> str:
    """Create detailed hover information for a network device."""
    vlans = ", ".join(device.vlans) if device.vlans else "None"
    protocols = ", ".join(device.routing_protocols) if device.routing_protocols else "None"

    return (
        f"<b>{device.hostname}</b><br>"
        f"Type: {device.device_type}<br>"
        f"Interfaces: {len(device.interfaces)}<br>"
        f"VLANs: {vlans}<br>"
        f"Routing: {protocols}<br>"
        f"Source: {device.source_file}"
    )