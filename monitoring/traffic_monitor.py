import random


def generate_traffic(graph):

    traffic_data = {}

    for edge in graph.edges:

        # Simulate traffic percentage
        traffic = random.randint(10, 100)

        traffic_data[edge] = traffic

    return traffic_data


def analyze_traffic(traffic_data):

    print("\n=== TRAFFIC ANALYSIS ===")

    alerts = []

    for link, usage in traffic_data.items():

        print(f"{link}: {usage}% utilization")

        if usage > 80:

            alert = (
                f"[WARNING] High traffic detected "
                f"on link {link} ({usage}%)"
            )

            alerts.append(alert)

    return alerts