from sqlalchemy import text

from backend.database import engine

from backend.notifications.email_service import (
    send_email_notification
)

from backend.notifications.telegram_service import (
    send_telegram_notification
)


def notification_exists(
    event_id,
    channel
):

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT 1
                FROM notification_log
                WHERE event_id = :event_id
                  AND notification_channel = :channel
                LIMIT 1
            """),
            {
                "event_id": event_id,
                "channel": channel
            }
        )

        return result.first() is not None


def save_notification(
    alert,
    channel
):

    with engine.begin() as connection:

        connection.execute(
            text("""
                INSERT INTO notification_log
                (
                    event_id,
                    notification_channel,
                    alert_level,
                    risk_score,
                    source_ip,
                    event_type
                )
                VALUES
                (
                    :event_id,
                    :channel,
                    :alert_level,
                    :risk_score,
                    :source_ip,
                    :event_type
                )
                ON CONFLICT
                (
                    event_id,
                    notification_channel
                )
                DO NOTHING
            """),
            {
                "event_id": alert["event_id"],
                "channel": channel,
                "alert_level": alert["alert_level"],
                "risk_score": alert["risk_score"],
                "source_ip": alert["source_ip"],
                "event_type": alert["event_type"]
            }
        )


def build_notification_message(alert):

    lines = [
        "CYBER DIGITAL TWIN SECURITY ALERT",
        "=" * 45,
    ]

    # Add SSH event details only for event-level notifications.
    if (
        alert.get("event_id")
        or alert.get("event_type")
        or alert.get("alert_level")
    ):

        lines.extend([
            "",
            "SSH EVENT DETAILS",
            f"Alert Level: {alert.get('alert_level', 'UNKNOWN')}",
            f"Event Risk Score: {alert.get('risk_score', 'N/A')}",
            f"Event Type: {alert.get('event_type', 'UNKNOWN')}",
            f"Username: {alert.get('username', 'UNKNOWN')}",
            f"Source IP: {alert.get('source_ip', 'UNKNOWN')}",
            f"Reason: {alert.get('reason', 'Not provided')}",
            f"Event Time: {alert.get('event_time', 'UNKNOWN')}",
        ])

    # Add incident intelligence only when supplied.
    if alert.get("incident_id"):

        lines.extend([
            "",
            "=" * 45,
            "CORRELATED INCIDENT INTELLIGENCE",
            f"Incident ID: {alert.get('incident_id')}",
            f"Incident Type: {alert.get('incident_type', 'UNKNOWN')}",
            f"Incident Severity: {alert.get('severity', 'UNKNOWN')}",
            f"AI Threat Score: {alert.get('threat_score', 'N/A')}/100",
            f"Priority: {alert.get('priority', 'UNKNOWN')}",
            f"AI Decision: {alert.get('ai_decision', 'UNKNOWN')}",
            f"Decision Explanation: {alert.get('decision_explanation', 'Not provided')}",
            f"Recommended Action: {alert.get('recommended_action', 'Not provided')}",
            f"Response Mode: {alert.get('response_mode', 'DRY-RUN')}",
            f"Source IP: {alert.get('source_ip', 'UNKNOWN')}",
            f"Target Host: {alert.get('target_hostname', 'UNKNOWN')}",
            f"Target IP: {alert.get('target_ip', 'UNKNOWN')}",
            f"Total Attempts: {alert.get('total_attempts', 'N/A')}",
            f"Failed Logins: {alert.get('failed_logins', 'N/A')}",
            f"Invalid Users: {alert.get('invalid_users', 'N/A')}",
            f"Attack Rate: {alert.get('attack_rate', 'N/A')} attempts/min",
            f"Related Event IDs: {alert.get('event_ids', [])}",
        ])

    lines.extend([
        "",
        "=" * 45,
        "Automated notification from AI-Powered Cyber Digital Twin.",
        "Response execution remains subject to configured security controls."
    ])

    return "\n".join(lines)


def send_alert_notifications(
    alert
):

    message = build_notification_message(
        alert
    )


    results = {}


    if not notification_exists(
        alert["event_id"],
        "email"
    ):

        email_sent = send_email_notification(
            subject=(
                "🚨 Cyber Digital Twin "
                f"{alert['alert_level']} Security Alert"
            ),
            message=message
        )

        results["email"] = email_sent


        if email_sent:

            save_notification(
                alert,
                "email"
            )

    else:

        print(
            f"📧 Email already sent for "
            f"event {alert['event_id']}."
        )

        results["email"] = "duplicate"


    if not notification_exists(
        alert["event_id"],
        "telegram"
    ):

        telegram_sent = (
            send_telegram_notification(
                message
            )
        )

        results["telegram"] = telegram_sent


        if telegram_sent:

            save_notification(
                alert,
                "telegram"
            )

    else:

        print(
            f"📱 Telegram already sent for "
            f"event {alert['event_id']}."
        )

        results["telegram"] = "duplicate"


    return results


def send_incident_email_notification(
    incident,
    decision
):
    """
    Send one incident-level email.

    Failed deliveries can be retried.
    Successful deliveries are never repeated.
    """

    incident_id = incident["incident_id"]

    # Reserve the notification attempt in the database.
    with engine.begin() as connection:

        result = connection.execute(
            text("""
                INSERT INTO incident_notification_log
                (
                    incident_id,
                    notification_channel,
                    severity,
                    threat_score,
                    priority,
                    source_ip,
                    delivery_status,
                    attempt_count,
                    last_attempt_at
                )
                VALUES
                (
                    :incident_id,
                    'email',
                    :severity,
                    :threat_score,
                    :priority,
                    :source_ip,
                    'PENDING',
                    1,
                    CURRENT_TIMESTAMP
                )

                ON CONFLICT
                (
                    incident_id,
                    notification_channel
                )

                DO UPDATE SET
                    delivery_status = 'PENDING',
                    attempt_count =
                        incident_notification_log.attempt_count + 1,
                    last_attempt_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP,
                    error_message = NULL

                WHERE
                    (
                        incident_notification_log.delivery_status = 'FAILED'
                        AND incident_notification_log.last_attempt_at
                            < CURRENT_TIMESTAMP - INTERVAL '5 minutes'
                    )
                    OR (
                        incident_notification_log.delivery_status = 'PENDING'
                        AND incident_notification_log.last_attempt_at
                            < CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                    )

                RETURNING id
            """),
            {
                "incident_id": incident_id,
                "severity": incident["severity"],
                "threat_score": decision["threat_score"],
                "priority": decision["priority"],
                "source_ip": incident["source_ip"]
            }
        )

        reserved = result.first()

    # No reservation means already sent or currently being processed.
    if reserved is None:

        print(
            f"Incident email skipped: {incident_id}"
        )

        return "duplicate_or_in_progress"

    # Prepare incident intelligence for the existing formatter.
    alert = {
        "incident_id": incident_id,
        "incident_type": incident["incident_type"],
        "severity": incident["severity"],
        "threat_score": decision["threat_score"],
        "priority": decision["priority"],
        "ai_decision": decision["decision"],
        "decision_explanation": decision["explanation"],
        "recommended_action": decision["recommended_action"],
        "response_mode": decision.get("execution_mode", "DRY-RUN"),
        "source_ip": incident["source_ip"],
        "target_hostname": incident["target_hostname"],
        "target_ip": incident["target_ip"],
        "total_attempts": incident["total_attempts"],
        "failed_logins": incident["failed_logins"],
        "invalid_users": incident["invalid_users"],
        "attack_rate": incident["attack_rate"],
        "event_ids": incident["event_ids"]
    }

    message = build_notification_message(alert)

    subject = (
        f"Cyber Digital Twin | "
        f"{incident['severity']} Incident | "
        f"{decision['priority']} | {incident_id}"
    )

    # Attempt delivery.
    try:

        email_sent = send_email_notification(
            subject=subject,
            message=message
        )

        if not email_sent:
            raise RuntimeError(
                "Email service reported delivery failure"
            )

        with engine.begin() as connection:

            connection.execute(
                text("""
                    UPDATE incident_notification_log
                    SET
                        delivery_status = 'SENT',
                        sent_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP,
                        error_message = NULL
                    WHERE id = :record_id
                """),
                {
                    "record_id": reserved.id
                }
            )

        return "sent"

    except Exception as error:

        with engine.begin() as connection:

            connection.execute(
                text("""
                    UPDATE incident_notification_log
                    SET
                        delivery_status = 'FAILED',
                        error_message = :error_message,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :record_id
                """),
                {
                    "record_id": reserved.id,
                    "error_message": str(error)[:2000]
                }
            )

        print(
            f"Incident email failed for {incident_id}: {error}"
        )

        return "failed"
