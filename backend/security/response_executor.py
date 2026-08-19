# ============================================================
# SECURITY RESPONSE EXECUTOR
# ============================================================
#
# Safe execution layer for the Cyber Digital Twin.
#
# Current mode: DRY-RUN
#
# This module receives decisions from the AI Security
# Decision Engine and safely simulates the response.
#
# No firewall, account, or network configuration is modified.
# ============================================================


from datetime import datetime, timezone


# ============================================================
# EXECUTION MODE
# ============================================================

EXECUTION_MODE = "DRY-RUN"


# ============================================================
# SECURITY RESPONSE EXECUTOR
# ============================================================

def execute_response(decision):

    """
    Safely process an AI security decision.

    Current implementation:
    DRY-RUN only.

    Supported decisions:

    MONITOR
    ENHANCED_MONITORING
    BLOCK_SOURCE_IP
    IMMEDIATE_CONTAINMENT

    No real security controls are modified.
    """

    source_ip = decision.get(
        "source_ip",
        "UNKNOWN"
    )

    action = decision.get(
        "decision"
    ) or decision.get(
        "recommended_action"
    ) or "UNKNOWN"

    severity = decision.get(
        "severity",
        "UNKNOWN"
    )

    threat_score = decision.get(
        "threat_score",
        0
    )

    priority = decision.get(
        "priority",
        "P4"
    )

    timestamp = datetime.now(timezone.utc).isoformat()

    # --------------------------------------------------------
    # MONITOR
    # --------------------------------------------------------

    if action == "MONITOR":

        message = (
            f"Would continue standard monitoring "
            f"for source IP {source_ip}"
        )

    # --------------------------------------------------------
    # ENHANCED MONITORING
    # --------------------------------------------------------

    elif action in (
        "ENHANCED_MONITORING",
        "MONITOR_SOURCE_IP"
    ):

        action = "ENHANCED_MONITORING"

        message = (
            f"Would increase monitoring and logging "
            f"for source IP {source_ip}"
        )

    # --------------------------------------------------------
    # BLOCK SOURCE IP
    # --------------------------------------------------------

    elif action == "BLOCK_SOURCE_IP":

        message = (
            f"Would block source IP {source_ip} "
            f"using the security response policy"
        )

    # --------------------------------------------------------
    # IMMEDIATE CONTAINMENT
    # --------------------------------------------------------

    elif action == "IMMEDIATE_CONTAINMENT":

        message = (
            f"Would immediately contain source IP "
            f"{source_ip} using the security response policy"
        )

    # --------------------------------------------------------
    # LOG ONLY
    # --------------------------------------------------------

    elif action == "LOG_ONLY":

        message = (
            f"Would record security activity from "
            f"source IP {source_ip}"
        )

    # --------------------------------------------------------
    # UNKNOWN
    # --------------------------------------------------------

    else:

        action = "UNKNOWN"

        message = (
            f"No execution policy exists for "
            f"the received security decision"
        )

    # --------------------------------------------------------
    # RETURN EXECUTION RESULT
    # --------------------------------------------------------

    return {

        "timestamp": timestamp,

        "executed": False,

        "mode": EXECUTION_MODE,

        "source_ip": source_ip,

        "severity": severity,

        "threat_score": threat_score,

        "priority": priority,

        "action": action,

        "message": message

    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_decision = {

        "source_ip": "192.168.38.146",

        "severity": "HIGH",

        "threat_score": 85,

        "priority": "P1",

        "decision": "BLOCK_SOURCE_IP"

    }

    result = execute_response(
        test_decision
    )

    print(
        "\n========== RESPONSE EXECUTION ==========\n"
    )

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )

    print(
        "\n========================================\n"
    )
