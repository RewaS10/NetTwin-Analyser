def analyze_configs(network_data):

    issues = []

    # Duplicate IP detection
    ip_map = {}

    for router in network_data:

        for ip in router["ips"]:

            if ip in ip_map:

                issues.append(
                    f"[CRITICAL] Duplicate IP detected: "
                    f"{ip} used by "
                    f"{router['hostname']} and "
                    f"{ip_map[ip]}"
                )

            else:
                ip_map[ip] = router["hostname"]

    # VLAN mismatch detection
    vlan_map = {}

    for router in network_data:

        for vlan in router["vlans"]:

            if vlan not in vlan_map:
                vlan_map[vlan] = []

            vlan_map[vlan].append(
                router["hostname"]
            )

    for vlan, routers in vlan_map.items():

        if len(routers) == 1:

            issues.append(
                f"[WARNING] VLAN {vlan} exists "
                f"only on {routers[0]} "
                f"(possible mismatch)"
            )

    # Missing IP detection
    for router in network_data:

        if len(router["ips"]) == 0:

            issues.append(
                f"[WARNING] "
                f"{router['hostname']} "
                f"has no IP configured"
            )

    return issues