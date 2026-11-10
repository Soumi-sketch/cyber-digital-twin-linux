# ============================================================
# INCIDENT ASSIGNMENT AND ACKNOWLEDGEMENT REMINDER MANAGER
# ============================================================

from datetime import datetime, timezone

from sqlalchemy import text

from backend.database import engine

from backend.security.incident_manager import (
    ensure_incident_open
)


# ------------------------------------------------------------
# REMINDER TIMING POLICY
# ------------------------------------------------------------

REMINDER_POLICY = {
    "HIGH": 10,
    "CRITICAL": 3
}


# ------------------------------------------------------------
# CURRENT UTC TIME
# ------------------------------------------------------------

def current_time():

    return datetime.now(
        timezone.utc
    ).replace(tzinfo=None)


# ------------------------------------------------------------
# GET INCIDENT LIFECYCLE AND WORKFLOW
# ------------------------------------------------------------

def get_reminder_lifecycle(incident_id):

    with engine.connect() as connection:

        lifecycle = connection.execute(
            text("""
                SELECT
                    (
                        SELECT status
                        FROM security_incident_status
                        WHERE incident_id = :incident_id
                        ORDER BY updated_at DESC, id DESC
                        LIMIT 1
                    ) AS status,

                    (
                        SELECT acknowledged_at
                        FROM security_incident_workflow
                        WHERE incident_id = :incident_id
                    ) AS acknowledged_at,

                    (
                        SELECT assigned_to_user_id
                        FROM security_incident_workflow
                        WHERE incident_id = :incident_id
                    ) AS assigned_to_user_id,

                    (
                        SELECT COUNT(*)
                        FROM security_incident_status
                        WHERE incident_id = :incident_id
                        AND action = 'REOPENED'
                    ) + 1 AS reminder_cycle,

                    (
                        SELECT MAX(updated_at)
                        FROM security_incident_status
                        WHERE incident_id = :incident_id
                        AND action IN (
                            'INCIDENT_REGISTERED',
                            'REOPENED'
                        )
                    ) AS cycle_anchor,

                    (
                        SELECT MAX(updated_at)
                        FROM security_incident_status
                        WHERE incident_id = :incident_id
                        AND action = 'ASSIGNED'
                    ) AS last_assigned_at
            """),
            {
                "incident_id": incident_id
            }
        ).mappings().first()

    if lifecycle is None or lifecycle["status"] is None:
        return None

    return dict(lifecycle)


# ------------------------------------------------------------
# GET ACTIVE ADMIN RECIPIENTS
# ------------------------------------------------------------

def get_active_admins():

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT id, username, role
                FROM users
                WHERE LOWER(role) = 'admin'
                AND is_active = TRUE
                ORDER BY id
            """)
        )

        return [
            dict(row)
            for row in result.mappings().all()
        ]


# ------------------------------------------------------------
# GET ASSIGNED ANALYST
# ------------------------------------------------------------

def get_assigned_analyst(user_id):

    if user_id is None:
        return None

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT id, username, role
                FROM users
                WHERE id = :user_id
                AND LOWER(role) = 'analyst'
                AND is_active = TRUE
            """),
            {
                "user_id": user_id
            }
        ).mappings().first()

    return dict(result) if result else None


# ------------------------------------------------------------
# CREATE DASHBOARD REMINDER
# ------------------------------------------------------------

def create_reminder(
    incident_id,
    cycle,
    reminder_type,
    severity,
    recipient,
    reminder_minutes
):

    with engine.begin() as connection:

        result = connection.execute(
            text("""
                INSERT INTO security_incident_reminders
                (
                    incident_id,
                    reminder_cycle,
                    reminder_type,
                    reminder_level,
                    severity,
                    recipient_user_id,
                    recipient_role,
                    reminder_after_minutes,
                    delivery_status,
                    triggered_at
                )

                VALUES
                (
                    :incident_id,
                    :cycle,
                    :reminder_type,
                    1,
                    :severity,
                    :recipient_user_id,
                    :recipient_role,
                    :reminder_minutes,
                    'CREATED',
                    CURRENT_TIMESTAMP
                )

                ON CONFLICT (
                    incident_id,
                    reminder_cycle,
                    reminder_type,
                    reminder_level,
                    recipient_user_id
                )
                DO NOTHING

                RETURNING id
            """),
            {
                "incident_id": incident_id,
                "cycle": cycle,
                "reminder_type": reminder_type,
                "severity": severity,
                "recipient_user_id": recipient["id"],
                "recipient_role": recipient["role"],
                "reminder_minutes": reminder_minutes
            }
        )

        created = result.first()

    if created is None:
        return None

    return created.id


# ------------------------------------------------------------
# PROCESS ONE INCIDENT
# ------------------------------------------------------------

def process_one_incident_reminder(incident):

    incident_id = incident["incident_id"]

    severity = str(
        incident.get("severity", "")
    ).strip().upper()

    if severity not in REMINDER_POLICY:
        return []

    # Ensure that the incident has lifecycle history.
    ensure_incident_open(incident_id)

    lifecycle = get_reminder_lifecycle(
        incident_id
    )

    if lifecycle is None:
        return []

    # Stop reminders for completed incidents.
    if lifecycle["status"] in (
        "RESOLVED",
        "CLOSED"
    ):
        return []

    # Stop reminders after acknowledgement.
    if lifecycle["acknowledged_at"] is not None:
        return []

    cycle = int(
        lifecycle["reminder_cycle"]
    )

    reminder_minutes = REMINDER_POLICY[
        severity
    ]

    now = current_time()

    results = []

    assigned_user_id = lifecycle[
        "assigned_to_user_id"
    ]

    # --------------------------------------------------------
    # CASE 1: INCIDENT IS UNASSIGNED
    # --------------------------------------------------------

    if assigned_user_id is None:

        anchor = lifecycle["cycle_anchor"]

        if anchor is None:
            return []

        elapsed = (
            now - anchor
        ).total_seconds()

        if elapsed < reminder_minutes * 60:
            return []

        recipients = get_active_admins()

        reminder_type = "UNASSIGNED"

    # --------------------------------------------------------
    # CASE 2: INCIDENT IS ASSIGNED BUT NOT ACKNOWLEDGED
    # --------------------------------------------------------

    else:

        assigned_at = lifecycle["last_assigned_at"]
        cycle_anchor = lifecycle["cycle_anchor"]

        if assigned_at is None or cycle_anchor is None:
            return []

        # Assignment must belong to the current cycle.
        reminder_anchor = max(
            assigned_at,
            cycle_anchor
        )

        elapsed = (
            now - reminder_anchor
        ).total_seconds()

        if elapsed < reminder_minutes * 60:
            return []

        recipients = get_active_admins()

        analyst = get_assigned_analyst(
            assigned_user_id
        )

        if analyst is not None:
            recipients.append(analyst)

        reminder_type = "ACKNOWLEDGEMENT"

    # --------------------------------------------------------
    # CREATE ONE REMINDER PER RECIPIENT
    # --------------------------------------------------------

    for recipient in recipients:

        reminder_id = create_reminder(
            incident_id=incident_id,
            cycle=cycle,
            reminder_type=reminder_type,
            severity=severity,
            recipient=recipient,
            reminder_minutes=reminder_minutes
        )

        if reminder_id is not None:

            results.append({
                "reminder_id": reminder_id,
                "incident_id": incident_id,
                "cycle": cycle,
                "type": reminder_type,
                "severity": severity,
                "recipient_user_id": recipient["id"],
                "recipient_role": recipient["role"],
                "result": "created"
            })

    return results


# ------------------------------------------------------------
# PROCESS ALL DETECTED INCIDENTS
# ------------------------------------------------------------

def process_incident_reminders(incidents=None):

    if incidents is None:

        from backend.security.incident_engine import (
            detect_ssh_incidents
        )

        incidents = detect_ssh_incidents()

    results = []

    for incident in incidents:

        try:

            incident_results = process_one_incident_reminder(
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
