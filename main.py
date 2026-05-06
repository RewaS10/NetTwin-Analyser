import argparse

from parser.config_parser import parse_all_configs

from topology.builder import (
    build_topology,
    print_topology,
    visualize_topology
)

from analyzer.checks import analyze_configs

from simulator.engine import (
    simulate_link_failure
)

from recommender.suggest import (
    generate_recommendations
)

from monitoring.traffic_monitor import (
    generate_traffic,
    analyze_traffic
)
from monitoring.network_metrics import (
    generate_network_metrics
)
from monitoring.log_analyzer import (
    analyze_logs
)
from security.acl_engine import (
    simulate_acl
)
from security.attack_simulator import (
    simulate_attack
)
from analyzer.routing_analysis import (
    analyze_routing_protocols
)
def main():

    parser = argparse.ArgumentParser(
        description="NetTwin Analyser"
    )
    parser.add_argument(
        "--logs",
        action="store_true",
        help="Analyze network logs"
    )
    parser.add_argument(
        "--acl",
        action="store_true",
        help="Run ACL simulation"
    )
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Run attack simulation"
    )
    parser.add_argument(
        "--routing",
        action="store_true",
        help="Analyze routing protocols"
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to config folder"
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run configuration analysis"
    )

    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Simulate link failure"
    )

    parser.add_argument(
        "--node1",
        type=str,
        help="First node"
    )

    parser.add_argument(
        "--node2",
        type=str,
        help="Second node"
    )

    parser.add_argument(
        "--visualize",
        action="store_true",
        help="Visualize topology"
    )

    args = parser.parse_args()

    # Parse configuration files
    data = parse_all_configs(args.input)

    # Build topology
    graph = build_topology(data)

    # Print topology
    print_topology(graph)

    # Generate traffic
    traffic_data = generate_traffic(graph)

    # Analyze traffic
    traffic_alerts = analyze_traffic(
        traffic_data
    )
        # Generate dashboard metrics
    metrics = generate_network_metrics(
        graph
    )

    # Default failure state
    failed_edge = None
    affected_nodes = []

    # Simulation
    if args.simulate:

        if args.node1 and args.node2:

            simulation_result = (
                simulate_link_failure(
                    graph,
                    args.node1,
                    args.node2
                )
            )

            failed_edge = simulation_result[
                "failed_edge"
            ]

            affected_nodes = simulation_result[
                "affected_nodes"
            ]

        else:

            print(
                "\n[ERROR] "
                "Provide --node1 and --node2"
            )

    # Visualization
    if args.visualize:

        visualize_topology(
            graph,
            traffic_data,
            failed_edge,
            affected_nodes,
            metrics
        )

    # Config analysis
    issues = []

    if args.analyze:

        issues = analyze_configs(data)

        print("\n=== ANALYSIS ===")

        if issues:

            for issue in issues:
                print(issue)

        else:
            print("No issues found")

    # Traffic alerts
    if traffic_alerts:

        print("\n=== TRAFFIC ALERTS ===")

        for alert in traffic_alerts:
            print(alert)
    # Log analysis
    if args.logs:

        analyze_logs(
            "logs/network.log"
        )
            # ACL simulation
    if args.acl:

        simulate_acl()
            # Attack simulation
    if args.attack:

        simulate_attack(
            graph
        )
        # Routing protocol analysis
    if args.routing:

        analyze_routing_protocols(
            data
        )
    # Recommendations
    if args.analyze:

        recommendations = (
            generate_recommendations(
                data,
                issues
            )
        )

        print("\n=== RECOMMENDATIONS ===")

        for rec in recommendations:
            print(f"- {rec}")


if __name__ == "__main__":
    main()