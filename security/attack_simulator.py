import random


def simulate_attack(graph):

    print("\n=== ATTACK SIMULATION ===")

    attack_types = [

        "DDoS Attack",
        "Brute Force Attempt",
        "Port Scanning",
        "Malware Traffic Spike"
    ]

    severity_levels = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    nodes = list(graph.nodes)

    if not nodes:

        print("No nodes available.")
        return

    target = random.choice(nodes)

    attack = random.choice(
        attack_types
    )

    severity = random.choice(
        severity_levels
    )

    print(
        f"Attack Type : {attack}"
    )

    print(
        f"Target Node : {target}"
    )

    print(
        f"Severity    : {severity}"
    )

    # Generate alert
    if severity in ["HIGH", "CRITICAL"]:

        print(
            "\n[ALERT] Immediate "
            "security response required."
        )

    else:

        print(
            "\n[INFO] Attack "
            "successfully monitored."
        )