def analyze_logs(log_file):

    print("\n=== LOG ANALYSIS ===")

    critical_count = 0
    warning_count = 0
    info_count = 0

    try:

        with open(log_file, "r") as file:

            lines = file.readlines()

    except Exception as e:

        print(f"[ERROR] {e}")
        return

    for line in lines:

        line = line.strip()

        if "[CRITICAL]" in line:

            critical_count += 1
            print(line)

        elif "[WARNING]" in line:

            warning_count += 1
            print(line)

        elif "[INFO]" in line:

            info_count += 1

    print("\n=== LOG SUMMARY ===")

    print(f"INFO Logs: {info_count}")
    print(f"WARNING Logs: {warning_count}")
    print(f"CRITICAL Logs: {critical_count}")

    if critical_count > 0:

        print(
            "\n[ALERT] "
            "Critical security/network events detected."
        )