import os
import re


def parse_config_file(file_path):

    router_data = {
        "hostname": None,
        "interfaces": [],
        "ips": [],
        "vlans": [],
        "device_type": "unknown",
        "routing_protocol": None
    }

    try:

        with open(file_path, 'r') as file:
            lines = file.readlines()

    except Exception as e:

        print(
            f"[ERROR] Could not read file "
            f"{file_path}: {e}"
        )

        return None

    for line in lines:

        line = line.strip()

        # Extract hostname
        if line.startswith("hostname"):

            parts = line.split()

            if len(parts) > 1:

                router_data["hostname"] = parts[1]

        # Extract device type
        if line.startswith("device"):

            parts = line.split()

            if len(parts) > 1:

                router_data["device_type"] = parts[1]

        # Extract routing protocol
        if line.startswith("router"):

            parts = line.split()

            if len(parts) > 1:

                router_data[
                    "routing_protocol"
                ] = parts[1].upper()

        # Extract interfaces
        if line.startswith("interface"):

            parts = line.split()

            if len(parts) > 1:

                router_data["interfaces"].append(
                    parts[1]
                )

        # Extract IP addresses
        ip_match = re.search(
            r'ip address (\d+\.\d+\.\d+\.\d+)',
            line
        )

        if ip_match:

            router_data["ips"].append(
                ip_match.group(1)
            )

        # Extract VLANs
        vlan_match = re.search(
            r'vlan (\d+)',
            line
        )

        if vlan_match:

            router_data["vlans"].append(
                vlan_match.group(1)
            )

    # Validate hostname
    if router_data["hostname"] is None:

        print(
            f"[WARNING] Skipping file "
            f"{file_path} "
            f"(missing hostname)"
        )

        return None

    return router_data


def parse_all_configs(folder_path):

    network_data = []

    if not os.path.exists(folder_path):

        print(
            f"[ERROR] Folder not found: "
            f"{folder_path}"
        )

        return []

    for filename in os.listdir(folder_path):

        if filename.endswith(".txt"):

            file_path = os.path.join(
                folder_path,
                filename
            )

            router_info = parse_config_file(
                file_path
            )

            if router_info is not None:

                network_data.append(
                    router_info
                )

    return network_data