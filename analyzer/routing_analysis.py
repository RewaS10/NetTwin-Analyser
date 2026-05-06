def analyze_routing_protocols(
    network_data
):

    print(
        "\n=== ROUTING PROTOCOL ANALYSIS ==="
    )

    protocol_count = {}

    for device in network_data:

        hostname = device["hostname"]

        protocol = device.get(
            "routing_protocol"
        )

        if protocol:

            print(
                f"{hostname} -> {protocol}"
            )

            if protocol not in protocol_count:

                protocol_count[
                    protocol
                ] = 0

            protocol_count[
                protocol
            ] += 1

    print("\n=== PROTOCOL SUMMARY ===")

    for protocol, count in protocol_count.items():

        print(
            f"{protocol}: "
            f"{count} device(s)"
        )

    if not protocol_count:

        print(
            "No routing protocols detected."
        )