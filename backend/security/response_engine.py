from datetime import datetime


# ============================================================
# SECURITY RESPONSE ENGINE
# ============================================================

def generate_response(incident):
    """
    Generate a recommended security response
    based on incident severity.

    This module is currently in DRY-RUN mode.
    It does NOT modify firewall rules.
    """

    severity = incident.get("severity")
    incident_type = incident.get("incident_type")
    source_ip = incident.get("source_ip")

    # --------------------------------------------------------
    # Determine recommended action
    # --------------------------------------------------------

    if severity == "CRITICAL":

        action = "IMMEDIATE_CONTAINMENT"
        description = (
            f"Immediately isolate or block source IP {source_ip}"
        )

    elif severity == "HIGH":

        action = "BLOCK_SOURCE_IP"
        description = (
            f"Recommend blocking source IP {source_ip}"
        )

    elif severity == "MEDIUM":

        action = "MONITOR_SOURCE_IP"
        description = (
            f"Increase monitoring for source IP {source_ip}"
        )

    else:

        action = "LOG_ONLY"
        description = (
            "Record the incident for security analysis"
        )

    # --------------------------------------------------------
    # Response object
    # --------------------------------------------------------

    return {
        "timestamp": datetime.utcnow().isoformat(),
        "incident_type": incident_type,
        "severity": severity,
        "source_ip": source_ip,
        "recommended_action": action,
        "description": description,
        "mode": "RECOMMENDATION"
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_incident = {
        "incident_type": "SSH_BRUTE_FORCE",
        "severity": "HIGH",
        "source_ip": "192.168.38.146"
    }

    response = generate_response(test_incident)

    print("\n================ SECURITY RESPONSE ================\n")

    for key, value in response.items():
        print(f"{key}: {value}")

    print(
        "\n====================================================\n"
    )
