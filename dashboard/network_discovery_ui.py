from __future__ import annotations

import streamlit as st

from network_discovery.file_handler import (
    SUPPORTED_EXTENSIONS,
    parse_uploaded_files,
)
from network_discovery.models import NetworkConnection
from network_discovery.topology_builder import build_topology
from dashboard.components.topology_visualizer import render_topology


def render_network_discovery():
    """Render the network configuration upload and discovery interface."""

    st.markdown(
        '<div class="section-title">Automatic Network Discovery</div>',
        unsafe_allow_html=True,
    )

    st.write(
        "Upload network device configuration files and let NetTwin "
        "automatically detect devices and reconstruct the network topology."
    )

    uploaded_files = st.file_uploader(
        "Upload Network Configuration Files",
        type=[ext.replace(".", "") for ext in SUPPORTED_EXTENSIONS],
        accept_multiple_files=True,
        help=(
            "Upload multiple Cisco-style configuration files. "
            "Supported formats: .txt, .cfg, .conf, .config"
        ),
        key="network_config_upload",
    )

    if not uploaded_files:
        st.info(
            "Upload one or more network configuration files "
            "to begin discovery."
        )
        return

    st.success(
        f"{len(uploaded_files)} file(s) uploaded successfully."
    )

    with st.expander("Uploaded Files", expanded=False):
        for uploaded_file in uploaded_files:
            st.write(f"- {uploaded_file.name}")

    if st.button(
        "Discover Network Topology",
        type="primary",
        use_container_width=True,
    ):
        with st.spinner("Analyzing network configurations..."):

            devices, errors = parse_uploaded_files(uploaded_files)

            if not devices:
                st.error("No network devices could be discovered.")

                for error in errors:
                    st.warning(error)

                return

            topology = build_topology(devices)

            # Convert any legacy tuple connections to
            # NetworkConnection objects.
            topology = _normalize_connections(topology)

            # Store the newly discovered topology.
            st.session_state["discovered_topology"] = topology
            st.session_state["discovery_errors"] = errors

    # Retrieve the most recently discovered topology.
    topology = st.session_state.get("discovered_topology")

    if topology is None:
        return

    # Normalize again in case an older topology exists in session state.
    topology = _normalize_connections(topology)
    st.session_state["discovered_topology"] = topology

    _render_discovery_results(topology)


def _normalize_connections(topology):
    """
    Convert legacy tuple connections into NetworkConnection objects.

    This keeps the application compatible with topology data created
    before NetworkConnection was introduced.
    """

    normalized_connections = []

    for connection in topology.connections:

        # Already using the new connection model.
        if isinstance(connection, NetworkConnection):
            normalized_connections.append(connection)
            continue

        # Legacy format:
        # ("R1", "R2")
        if isinstance(connection, tuple) and len(connection) >= 2:

            normalized_connections.append(
                NetworkConnection(
                    device_a=connection[0],
                    device_b=connection[1],
                    confidence="Low",
                    evidence=["Legacy tuple connection"],
                )
            )

    topology.connections = normalized_connections

    return topology


def _render_discovery_results(topology):
    """Render discovered devices and topology summary."""

    st.markdown("### Discovery Results")

    # ---------------------------------------------------------
    # Summary metrics
    # ---------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Devices Discovered",
        topology.device_count,
    )

    col2.metric(
        "Connections Found",
        len(topology.connections),
    )

    device_types = {
        device.device_type
        for device in topology.devices
    }

    col3.metric(
        "Device Types",
        len(device_types),
    )

    # ---------------------------------------------------------
    # Network topology visualization
    # ---------------------------------------------------------

    st.markdown("---")
    st.markdown("### Network Topology")

    render_topology(topology)

    # ---------------------------------------------------------
    # Discovered devices
    # ---------------------------------------------------------

    st.markdown("---")
    st.markdown("### Discovered Devices")

    for device in topology.devices:

        with st.expander(
            f"{device.hostname} ({device.device_type})"
        ):

            st.write(
                f"**Source File:** {device.source_file}"
            )

            st.write(
                f"**Interfaces Discovered:** "
                f"{len(device.interfaces)}"
            )

            if device.vlans:
                st.write(
                    "**VLANs:** "
                    + ", ".join(device.vlans)
                )

            if device.routing_protocols:
                st.write(
                    "**Routing Protocols:** "
                    + ", ".join(device.routing_protocols)
                )

            if device.interfaces:

                st.markdown("#### Interfaces")

                for interface in device.interfaces:
                    _render_interface(interface)

    # ---------------------------------------------------------
    # Discovered connections
    # ---------------------------------------------------------

    st.markdown("---")
    st.markdown("### Discovered Connections")

    if not topology.connections:

        st.warning(
            "No connections could be confidently inferred "
            "from the uploaded files."
        )

    else:

        confidence_icons = {
            "High": "🟢",
            "Medium": "🟡",
            "Low": "🟠",
        }

        for connection in topology.connections:

            icon = confidence_icons.get(
                connection.confidence,
                "⚪",
            )

            with st.expander(
                f"{icon} "
                f"{connection.device_a} ↔ "
                f"{connection.device_b} "
                f"({connection.confidence} Confidence)"
            ):

                st.write(
                    f"**Connection:** "
                    f"{connection.device_a} ↔ "
                    f"{connection.device_b}"
                )

                st.write(
                    f"**Confidence:** "
                    f"{connection.confidence}"
                )

                st.write("**Evidence:**")

                for item in connection.evidence:
                    st.write(f"• {item}")

    # ---------------------------------------------------------
    # Processing warnings
    # ---------------------------------------------------------

    errors = st.session_state.get(
        "discovery_errors",
        [],
    )

    if errors:

        with st.expander("Processing Warnings"):

            for error in errors:
                st.warning(error)


def _render_interface(interface) -> None:
    """Render a single interface's status and description."""

    status_label = (
        "UP"
        if interface.is_up
        else "DOWN"
    )

    ip_info = (
        interface.ip_address
        or "No IP"
    )

    st.write(
        f"**{interface.name}** "
        f"[{status_label}] - {ip_info}"
    )

    if interface.description:
        st.caption(interface.description)