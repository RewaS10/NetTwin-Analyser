acl_rules = {

    "R1": [

        {
            "action": "ALLOW",
            "network": "192.168"
        },

        {
            "action": "DENY",
            "network": "10.0"
        }
    ]
}


def check_acl(router, destination_ip):

    rules = acl_rules.get(router, [])

    for rule in rules:

        if destination_ip.startswith(
            rule["network"]
        ):

            return rule["action"]

    return "DENY"


def simulate_acl():

    print("\n=== ACL SIMULATION ===")

    test_cases = [

        ("R1", "192.168.1.10"),
        ("R1", "10.0.0.5"),
        ("R1", "172.16.1.1")
    ]

    for router, ip in test_cases:

        result = check_acl(
            router,
            ip
        )

        if result == "ALLOW":

            print(
                f"{router} -> {ip} : "
                f"ALLOWED"
            )

        else:

            print(
                f"{router} -> {ip} : "
                f"BLOCKED"
            )