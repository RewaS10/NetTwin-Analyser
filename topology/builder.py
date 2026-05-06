import networkx as nx
import matplotlib.pyplot as plt

from matplotlib.lines import Line2D


def build_topology(network_data):

    G = nx.Graph()

    # Add nodes
    for router in network_data:

        hostname = router["hostname"]

        if hostname is not None:

            G.add_node(
                hostname,
                ips=router["ips"],
                vlans=router["vlans"],
                device_type=router["device_type"]
            )

    # Add edges based on subnet matching
    for i in range(len(network_data)):

        for j in range(i + 1, len(network_data)):

            r1 = network_data[i]
            r2 = network_data[j]

            if (
                r1["hostname"] is None or
                r2["hostname"] is None
            ):
                continue

            for ip1 in r1["ips"]:

                for ip2 in r2["ips"]:

                    # Compare subnet
                    if (
                        ip1.split('.')[:3] ==
                        ip2.split('.')[:3]
                    ):

                        G.add_edge(
                            r1["hostname"],
                            r2["hostname"]
                        )

    return G


def print_topology(G):

    print("\n=== TOPOLOGY ===")

    for node in G.nodes:

        neighbors = list(G.neighbors(node))

        print(f"{node} -> {neighbors}")


def visualize_topology(
    G,
    traffic_data=None,
    failed_edge=None,
    affected_nodes=None,
    metrics=None
):

    print(
        "\nGenerating network graph visualization..."
    )

    plt.figure(figsize=(14, 9))

    # Layout
    pos = nx.spring_layout(
        G,
        seed=42
    )

    # Default affected nodes
    if affected_nodes is None:
        affected_nodes = []

    # Node colors
    node_colors = []

    for node in G.nodes:

        # Disconnected nodes
        if node in affected_nodes:

            node_colors.append("darkred")
            continue

        device_type = G.nodes[node].get(
            "device_type",
            "unknown"
        )

        if device_type == "router":
            node_colors.append("orange")

        elif device_type == "switch":
            node_colors.append("lightblue")

        elif device_type == "server":
            node_colors.append("lightgreen")

        else:
            node_colors.append("gray")

    # Separate edges
    normal_edges = []
    failed_edges = []

    for edge in G.edges:

        if (
            failed_edge and
            (
                edge == failed_edge or
                edge[::-1] == failed_edge
            )
        ):

            failed_edges.append(edge)

        else:
            normal_edges.append(edge)

    # Edge colors and labels
    edge_colors = []
    edge_labels = {}

    for edge in normal_edges:

        usage = 0

        if traffic_data:
            usage = traffic_data.get(edge, 0)

        edge_labels[edge] = f"{usage}%"

        if usage > 80:
            edge_colors.append("red")

        elif usage > 50:
            edge_colors.append("orange")

        else:
            edge_colors.append("green")

    # Draw nodes
    nx.draw_networkx_nodes(
        G,
        pos,
        node_color=node_colors,
        node_size=3500
    )

    # Draw labels
    nx.draw_networkx_labels(
        G,
        pos,
        font_size=12,
        font_weight="bold"
    )

    # Draw normal edges
    nx.draw_networkx_edges(
        G,
        pos,
        edgelist=normal_edges,
        edge_color=edge_colors,
        width=3
    )

    # Draw failed edges
    if failed_edges:

        nx.draw_networkx_edges(
            G,
            pos,
            edgelist=failed_edges,
            edge_color="darkred",
            style="dashed",
            width=4
        )

    # Draw edge labels
    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        font_size=10
    )

    # Dashboard title
    plt.title(
        "NetTwin Analyser - Network Monitoring Dashboard",
        fontsize=16,
        fontweight="bold"
    )

    # Metrics panel
    if metrics:

        metrics_text = (
            f"NETWORK METRICS\n\n"
            f"Nodes: {metrics['total_nodes']}\n"
            f"Links: {metrics['total_links']}\n"
            f"Uptime: {metrics['uptime']}%\n"
            f"Latency: {metrics['latency']} ms\n"
            f"Packet Loss: {metrics['packet_loss']}%\n"
            f"Health Score: {metrics['health_score']}/100"
        )

        plt.gcf().text(
            0.02,
            0.55,
            metrics_text,
            fontsize=11,
            bbox=dict(
                facecolor='white',
                edgecolor='black',
                boxstyle='round,pad=1'
            )
        )

    # Legend
    legend_elements = [

        Line2D(
            [0],
            [0],
            marker='o',
            color='w',
            label='Router',
            markerfacecolor='orange',
            markersize=12
        ),

        Line2D(
            [0],
            [0],
            marker='o',
            color='w',
            label='Switch',
            markerfacecolor='lightblue',
            markersize=12
        ),

        Line2D(
            [0],
            [0],
            marker='o',
            color='w',
            label='Server',
            markerfacecolor='lightgreen',
            markersize=12
        ),

        Line2D(
            [0],
            [0],
            marker='o',
            color='w',
            label='Disconnected Node',
            markerfacecolor='darkred',
            markersize=12
        ),

        Line2D(
            [0],
            [0],
            color='green',
            lw=3,
            label='Healthy Link'
        ),

        Line2D(
            [0],
            [0],
            color='orange',
            lw=3,
            label='Medium Traffic'
        ),

        Line2D(
            [0],
            [0],
            color='red',
            lw=3,
            label='High Traffic'
        ),

        Line2D(
            [0],
            [0],
            color='darkred',
            lw=3,
            linestyle='dashed',
            label='Failed Link'
        )
    ]

    plt.legend(
        handles=legend_elements,
        loc='upper right'
    )

    plt.axis("off")

    plt.show()