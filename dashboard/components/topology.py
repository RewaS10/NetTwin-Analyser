from pyvis.network import Network

import tempfile


def render_topology(
    graph,
    traffic_load=50,
    scenario="Normal Operation"
):

    net = Network(
        height="650px",
        width="100%",
        bgcolor="#0b0f19",
        font_color="white",
        directed=False
    )

    # Physics settings
    net.barnes_hut()

    # Add nodes
    for node in graph.nodes:

        node_data = graph.nodes[node]

        device_type = node_data.get(
            "device_type",
            "router"
        )

        if device_type == "router":

            color = "#ffb703"
            shape = "dot"
            size = 35

        elif device_type == "switch":

            color = "#00f5ff"
            shape = "square"
            size = 30

        elif device_type == "server":

            color = "#00ff9f"
            shape = "triangle"
            size = 30

        else:

            color = "#9ca3af"
            shape = "dot"
            size = 25

        tooltip = f"""
        Hostname: {node}
        Type: {device_type}
        IPs: {node_data.get('ips', [])}
        Routing: {node_data.get('routing_protocol', 'Unknown')}
        Health: 92%
        """

        net.add_node(

            node,

            label=node,

            title=tooltip,

            color=color,

            shape=shape,

            size=size,

            borderWidth=3
        )

    # Add edges
    for edge in graph.edges:

        src, dst = edge

        latency = round(
            traffic_load * 0.3,
            2
        )

        packet_loss = round(
            traffic_load * 0.02,
            2
        )

        tooltip = f"""
        Traffic: {traffic_load}%
        Latency: {latency} ms
        Packet Loss: {packet_loss}%
        Status: Healthy
        """

        color = "#00f5ff"
        width = 2

        # Scenario-based styling
        if traffic_load > 80:

            color = "#ff4d6d"
            width = 6

        elif traffic_load > 50:

            color = "#ffb703"
            width = 4

        if scenario == "Link Failure":

            color = "#ff4d6d"

        net.add_edge(

            src,

            dst,

            title=tooltip,

            color=color,

            width=width
        )

    # Advanced physics/settings
    net.set_options(
        """
        var options = {

          "nodes": {
            "font": {
              "size": 18,
              "face": "arial",
              "color": "#ffffff"
            }
          },

          "edges": {
            "smooth": {
              "type": "dynamic"
            }
          },

          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -3000,
              "springLength": 220
            },
            "minVelocity": 0.75
          }
        }
        """
    )

    # Save temporary html
    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".html"
    )

    net.save_graph(temp_file.name)

    return temp_file.name