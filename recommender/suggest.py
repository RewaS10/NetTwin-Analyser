def generate_recommendations(
    network_data,
    issues
):

    recommendations = []

    # Recommendations from issues
    for issue in issues:

        if "Duplicate IP" in issue:

            recommendations.append(
                "Resolve duplicate IP conflicts "
                "by assigning unique IP addresses."
            )

        if "VLAN" in issue:

            recommendations.append(
                "Ensure consistent VLAN "
                "configuration across routers."
            )

        if "no IP configured" in issue:

            recommendations.append(
                "Assign IP addresses to all "
                "routers/interfaces."
            )

    # General recommendations
    if len(network_data) >= 3:

        recommendations.append(
            "Consider implementing redundancy "
            "(backup paths) to improve "
            "fault tolerance."
        )

    if len(network_data) > 5:

        recommendations.append(
            "Network size is growing — "
            "consider dynamic routing "
            "protocols like OSPF or BGP."
        )

    return list(set(recommendations))