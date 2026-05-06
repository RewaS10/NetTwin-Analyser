import networkx as nx


def simulate_link_failure(
    graph,
    node1,
    node2
):

    print("\n=== SIMULATION ===")

    print(
        f"Simulating failure between "
        f"{node1} and {node2}"
    )

    if not graph.has_edge(node1, node2):

        print("No such link exists.")

        return {
            "failed_edge": None,
            "affected_nodes": []
        }

    # Create temporary graph
    temp_graph = graph.copy()

    # Remove failed edge
    temp_graph.remove_edge(
        node1,
        node2
    )

    affected_nodes = []

    # Detect disconnected nodes
    for node in temp_graph.nodes:

        if node == node1:
            continue

        if not nx.has_path(
            temp_graph,
            node1,
            node
        ):

            affected_nodes.append(node)

    if affected_nodes:

        print(
            "Affected nodes:",
            affected_nodes
        )

    else:

        print(
            "No nodes affected. "
            "Network still connected."
        )

    return {
        "failed_edge": (node1, node2),
        "affected_nodes": affected_nodes
    }