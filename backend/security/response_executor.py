# ============================================================
# SECURITY RESPONSE EXECUTOR
# ============================================================
#
# Safe execution layer for the Cyber Digital Twin.
# Current mode: DRY-RUN
#
# No firewall or network configuration is modified.
# ============================================================


def execute_response(incident):
    """
    Execute the recommended security response.

    Current implementation is DRY-RUN only.
    It reports what action would be performed.
    """

    severity = incident.get("severity")
    source_ip = incident.get("source_ip")
    action = incident.get("recommended_action")

    # --------------------------------------------------------
    # MONITOR
    # --------------------------------------------------------

    if action == "MONITOR_SOURCE_IP":

        return {
            "executed": False,
            "mode": "DRY-RUN",
            "action": "MONITOR_SOURCE_IP",
            "source_ip": source_ip,
            "message": (
                f"Would increase monitoring for "
                f"source IP {source_ip}"
            )
        }

    # --------------------------------------------------------
    # BLOCK
    # --------------------------------------------------------

    elif action == "BLOCK_SOURCE_IP":

        return {
            "executed": False,
            "mode": "DRY-RUN",
            "action": "BLOCK_SOURCE_IP",
            "source_ip": source_ip,
            "message": (
                f"Would block source IP {source_ip}"
            )
        }

    # --------------------------------------------------------
    # IMMEDIATE CONTAINMENT
    # --------------------------------------------------------

    elif action == "IMMEDIATE_CONTAINMENT":

        return {
            "executed": False,
            "mode": "DRY-RUN",
            "action": "IMMEDIATE_CONTAINMENT",
            "source_ip": source_ip,
            "message": (
                f"Would immediately isolate or "
                f"block source IP {source_ip}"
            )
        }

    # --------------------------------------------------------
    # LOG ONLY
    # --------------------------------------------------------

    elif action == "LOG_ONLY":

        return {
            "executed": False,
            "mode": "DRY-RUN",
            "action": "LOG_ONLY",
            "source_ip": source_ip,
            "message": (
                "Would record the incident "
                "for security analysis"
            )
        }

    # --------------------------------------------------------
    # UNKNOWN ACTION
    # --------------------------------------------------------

    return {
        "executed": False,
        "mode": "DRY-RUN",
        "action": "UNKNOWN",
        "source_ip": source_ip,
        "message": (
            f"No execution rule exists for "
            f"severity {severity}"
        )
    }
