import random


def generate_network_metrics(graph):

    metrics = {}

    total_links = len(graph.edges)

    # Simulated uptime
    uptime = round(
        random.uniform(95.0, 99.9),
        2
    )

    # Simulated packet loss
    packet_loss = round(
        random.uniform(0.0, 5.0),
        2
    )

    # Simulated latency
    latency = round(
        random.uniform(5.0, 120.0),
        2
    )

    # Health score
    health_score = 100

    if packet_loss > 3:
        health_score -= 20

    if latency > 80:
        health_score -= 20

    metrics["total_nodes"] = len(graph.nodes)
    metrics["total_links"] = total_links
    metrics["uptime"] = uptime
    metrics["packet_loss"] = packet_loss
    metrics["latency"] = latency
    metrics["health_score"] = health_score

    return metrics