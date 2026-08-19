# ============================================================
# SECURITY RESPONSE EXECUTOR
# ============================================================
#
# Safe execution layer for the Cyber Digital Twin.
#
# Current mode: DRY-RUN
#
# Every response is recorded in PostgreSQL for audit purposes.
#
# No firewall, account, or network configuration is modified.
# ============================================================

from datetime import datetime, timezone

from backend.database import SessionLocal
from backend.models.security_response_audit import SecurityResponseAudit


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
    LOG_ONLY

    Every execution is recorded in the
    security_response_audit PostgreSQL table.

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

    incident_id = decision.get(
        "incident_id",
        "UNKNOWN"
    )

    incident_type = decision.get(
        "incident_type",
        "UNKNOWN"
    )

    confidence_score = decision.get(
        "confidence_score",
        0
    )

    confidence_level = decision.get(
        "confidence_level",
        "UNKNOWN"
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
    # DATABASE AUDIT
    # --------------------------------------------------------

    audit_saved = False
    audit_duplicate = False

    db = None

    try:

        db = SessionLocal()

        # ----------------------------------------------------
        # DUPLICATE PROTECTION
        # ----------------------------------------------------

        existing_record = (
            db.query(SecurityResponseAudit)
            .filter(
                SecurityResponseAudit.incident_id == incident_id,
                SecurityResponseAudit.execution_action == action,
                SecurityResponseAudit.execution_mode == EXECUTION_MODE
            )
            .first()
        )

        if existing_record:

            audit_duplicate = True

            print(
                f"[AUDIT] Existing record found for "
                f"incident {incident_id} "
                f"with action {action}. "
                f"Skipping duplicate."
            )

        else:

            audit_record = SecurityResponseAudit(

                incident_id=incident_id,

                incident_type=incident_type,

                severity=severity,

                source_ip=source_ip,

                threat_score=threat_score,

                priority=priority,

                ai_decision=action,

                recommended_action=decision.get(
                    "recommended_action",
                    action
                ),

                confidence_score=confidence_score,

                confidence_level=confidence_level,

                execution_mode=EXECUTION_MODE,

                executed=False,

                execution_action=action,

                execution_message=message
            )

            db.add(audit_record)

            db.commit()

            audit_saved = True

    except Exception as exc:

        if db is not None:
            db.rollback()

        print(
            f"[AUDIT ERROR] Could not save "
            f"security response audit: {exc}"
        )

    finally:

        if db is not None:
            db.close()


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

        "message": message,

        "audit_saved": audit_saved,

        "audit_duplicate": audit_duplicate

    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_decision = {

        "incident_id": "TEST-AUDIT-001",

        "incident_type": "SSH_BRUTE_FORCE",

        "source_ip": "192.168.38.146",

        "severity": "HIGH",

        "threat_score": 85,

        "priority": "P1",

        "decision": "BLOCK_SOURCE_IP",

        "recommended_action": "BLOCK_SOURCE_IP",

        "confidence_score": 70,

        "confidence_level": "HIGH"

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
