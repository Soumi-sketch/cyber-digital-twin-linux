
# ============================================================
# INCIDENT ESCALATION MANAGER
# ============================================================

import os
from datetime import datetime, timezone

from sqlalchemy import text

from backend.database import engine

from backend.security.incident_manager import (
    ensure_incident_open
)

from backend.notifications.notification_policy import (
    should_send_notification
)

from backend.notifications.email_service import (
    send_email_notification
)

from backend.notifications.telegram_service import (
    send_telegram_notification
)


# ------------------------------------------------------------
# ESCALATION TIMING POLICY
# ------------------------------------------------------------

ESCALATION_POLICY = {
    "HIGH": {
        1: 15,
        2: 30
    },
    "CRITICAL": {
        1: 5,
        2: 10
    }
}


# ------------------------------------------------------------
# CURRENT UTC TIME
# ------------------------------------------------------------

def current_time():

    return datetime.now(
        timezone.utc
    ).replace(tzinfo=None)


# ------------------------------------------------------------
# GET INCIDENT LIFECYCLE INFORMATION
# ------------------------------------------------------------

def get_incident_lifecycle(incident_id):

    with engine.connect() as connection:

        latest = connection.execute(
            text("""
                SELECT status
                FROM security_incident_status
                WHERE incident_id = :incident_id
                ORDER BY updated_at DESC, id DESC
                LIMIT 1
            """),
            {
                "incident_id": incident_id
            }
        ).first()

        workflow = connection.execute(
            text("""
                SELECT acknowledged_at
                FROM security_incident_workflow
                WHERE incident_id = :incident_id
            """),
            {
                "incident_id": incident_id
            }
        ).first()

        cycle_data = connection.execute(
            text("""
                SELECT
                    COUNT(*) FILTER (
                        WHERE action = 'REOPENED'
                    ) AS reopened_count,

                    MAX(updated_at) FILTER (
                        WHERE action IN (
                            'INCIDENT_REGISTERED',
                            'REOPENED'
                        )
                    ) AS escalation_anchor

                FROM security_incident_status

                WHERE incident_id = :incident_id
            """),
            {
                "incident_id": incident_id
            }
        ).first()

    if latest is None or cycle_data is None:
        return None

    return {
        "status": latest.status,
        "acknowledged_at": (
            workflow.acknowledged_at
            if workflow else None
        ),
        "cycle": int(cycle_data.reopened_count or 0) + 1,
        "anchor": cycle_data.escalation_anchor
    }


# ------------------------------------------------------------
# RESERVE ESCALATION RECORD
# ------------------------------------------------------------

def reserve_escalation(
    incident_id,
    cycle,
    level,
    severity,
    channel
):

    with engine.begin() as connection:

        result = connection.execute(
            text("""
                INSERT INTO security_incident_escalations
                (
                    incident_id,
                    escalation_cycle,
                    escalation_level,
                    severity,
                    notification_channel,
                    delivery_status,
                    triggered_at
                )

                VALUES
                (
                    :incident_id,
                    :cycle,
                    :level,
                    :severity,
                    :channel,
                    'PENDING',
                    CURRENT_TIMESTAMP
                )

                ON CONFLICT (
                    incident_id,
                    escalation_cycle,
                    escalation_level,
                    notification_channel
                )

                DO UPDATE SET
                    delivery_status = 'PENDING',
                    triggered_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP,
                    error_message = NULL

                WHERE
                    (
                        security_incident_escalations.delivery_status = 'FAILED'
                        AND security_incident_escalations.triggered_at
                            < CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                    )

                    OR

                    (
                        security_incident_escalations.delivery_status = 'PENDING'
                        AND security_incident_escalations.triggered_at
                            < CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                    )

                RETURNING id
            """),
            {
                "incident_id": incident_id,
                "cycle": cycle,
                "level": level,
                "severity": severity,
                "channel": channel
            }
        )

        return result.first()


# ------------------------------------------------------------
# UPDATE ESCALATION DELIVERY STATUS
# ------------------------------------------------------------

def update_escalation_status(
    record_id,
    status,
    error_message=None
):

    with engine.begin() as connection:

        connection.execute(
            text("""
                UPDATE security_incident_escalations

                SET
                    delivery_status = :status,

                    sent_at = CASE
                        WHEN :status = 'SENT'
                        THEN CURRENT_TIMESTAMP
                        ELSE sent_at
                    END,

                    error_message = :error_message,

                    updated_at = CURRENT_TIMESTAMP

                WHERE id = :record_id
            """),
            {
                "record_id": record_id,
                "status": status,
                "error_message": (
                    str(error_message)[:2000]
                    if error_message else None
                )
            }
        )


# ------------------------------------------------------------
# SEND ESCALATION NOTIFICATION
# ------------------------------------------------------------

def send_escalation(
    incident,
    level,
    channel,
    cycle
):

    incident_id = incident["incident_id"]

    severity = incident["severity"]

    # Independent safety switch.
    # Escalation delivery remains disabled unless explicitly enabled.
    delivery_enabled = os.getenv(
        "ESCALATION_DELIVERY_ENABLED",
        "false"
    ).strip().lower() == "true"

    if not delivery_enabled:
        return "delivery_disabled"

    if not should_send_notification(
        severity,
        channel
    ):
        return "policy_blocked"

    reserved = reserve_escalation(
        incident_id=incident_id,
        cycle=cycle,
        level=level,
        severity=severity,
        channel=channel
    )

    if reserved is None:
        return "duplicate_or_in_progress"

    message = (
        "CYBER DIGITAL TWIN - INCIDENT ESCALATION\n\n"
        f"Incident ID: {incident_id}\n"
        f"Severity: {severity}\n"
        f"Escalation Level: {level}\n"
        f"Escalation Cycle: {cycle}\n"
        f"Source IP: {incident.get('source_ip')}\n"
        f"Target: {incident.get('target_hostname')}\n"
        f"Total Attempts: {incident.get('total_attempts')}\n\n"
        "The incident remains unacknowledged.\n"
        "Please investigate immediately.\n\n"
        "Response Mode: DRY-RUN"
    )

    try:

        if channel == "email":

            success = send_email_notification(
                subject=(
                    f"ESCALATION L{level} | "
                    f"{severity} | {incident_id}"
                ),
                message=message
            )

        elif channel == "telegram":

            success = send_telegram_notification(
                message
            )

        else:

            raise ValueError(
                f"Unsupported channel: {channel}"
            )

        if not success:
            raise RuntimeError(
                f"{channel} delivery failed"
            )

        update_escalation_status(
            reserved.id,
            "SENT"
        )

        return "sent"

    except Exception as error:

        update_escalation_status(
            reserved.id,
            "FAILED",
            error
        )

        return "failed"


# ------------------------------------------------------------
# PROCESS ONE INCIDENT
# ------------------------------------------------------------

def process_one_incident(incident):

    incident_id = incident["incident_id"]

    severity = incident.get("severity", "").upper()

    if severity not in ESCALATION_POLICY:
        return []

    # Register incident if it has no lifecycle history.
    ensure_incident_open(incident_id)

    lifecycle = get_incident_lifecycle(
        incident_id
    )

    if lifecycle is None:
        return []

    # Stop escalation for acknowledged incidents.
    if lifecycle["acknowledged_at"] is not None:
        return []

    # Stop escalation for completed incidents.
    if lifecycle["status"] in (
        "RESOLVED",
        "CLOSED"
    ):
        return []

    anchor = lifecycle["anchor"]

    if anchor is None:
        return []

    elapsed_seconds = (
        current_time() - anchor
    ).total_seconds()

    results = []

    # --------------------------------------------------------
    # CHECK ESCALATION LEVELS
    # --------------------------------------------------------

    for level, minutes in ESCALATION_POLICY[severity].items():

        threshold_seconds = minutes * 60

        if elapsed_seconds < threshold_seconds:
            continue

        channels = ["email"]

        if severity == "CRITICAL":
            channels.append("telegram")

        for channel in channels:

            result = send_escalation(
                incident=incident,
                level=level,
                channel=channel,
                cycle=lifecycle["cycle"]
            )

            results.append({
                "incident_id": incident_id,
                "severity": severity,
                "level": level,
                "cycle": lifecycle["cycle"],
                "channel": channel,
                "result": result
            })

    return results


# ------------------------------------------------------------
# PROCESS ALL DETECTED INCIDENTS
# ------------------------------------------------------------

def process_incident_escalations(incidents=None):

    if incidents is None:

        from backend.security.incident_engine import (
            detect_ssh_incidents
        )

        incidents = detect_ssh_incidents()

    results = []

    for incident in incidents:

        try:

            incident_results = process_one_incident(
                incident
            )

            results.extend(
                incident_results
            )

        except Exception as error:

            results.append({
                "incident_id": incident.get("incident_id"),
                "result": "error",
                "reason": str(error)
            })

    return results
