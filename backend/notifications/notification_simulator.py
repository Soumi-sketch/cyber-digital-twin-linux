
import json

from sqlalchemy import text

from backend.database import engine

from backend.notifications.notification_policy import (
    get_notification_policy
)


def simulate_notification_policy(
    severity,
    simulated_by_user_id,
    simulated_by_username
):
    """
    Evaluate notification policies without sending messages.

    STRICT DRY-RUN:
    - Does not send email.
    - Does not send Telegram messages.
    - Does not execute notification delivery functions.
    - Stores only simulation results.
    """

    normalized_severity = str(
        severity
    ).strip().upper()

    # Read the current database-backed policy.
    policy = get_notification_policy(
        normalized_severity
    )

    # Evaluate each notification channel.
    channels = {}

    for channel in (
        "email",
        "telegram",
        "dashboard"
    ):

        allowed = bool(
            policy[channel]
        )

        channels[channel] = {
            "allowed": allowed,
            "status": (
                "WOULD BE ALLOWED - NOT SENT"
                if allowed
                else "BLOCKED BY POLICY"
            ),
            "reason": (
                "Enabled in the current notification policy."
                if allowed
                else "Disabled by the current notification policy or safe fallback."
            )
        }

    # Store a snapshot of the evaluated policy.
    policy_snapshot = {
        "severity": normalized_severity,
        "priority": policy["priority"],
        "channels": channels,
        "mode": "DRY-RUN",
        "delivery_performed": False
    }

    # Persist simulation history only.
    with engine.begin() as connection:

        result = connection.execute(
            text("""
                INSERT INTO notification_simulation_history
                (
                    severity,
                    priority,
                    email_allowed,
                    telegram_allowed,
                    dashboard_allowed,
                    policy_snapshot,
                    simulation_mode,
                    simulated_by_user_id,
                    simulated_by_username
                )
                VALUES
                (
                    :severity,
                    :priority,
                    :email_allowed,
                    :telegram_allowed,
                    :dashboard_allowed,
                    CAST(:policy_snapshot AS JSONB),
                    'DRY-RUN',
                    :user_id,
                    :username
                )
                RETURNING id, created_at
            """),
            {
                "severity": normalized_severity,
                "priority": policy["priority"],
                "email_allowed": policy["email"],
                "telegram_allowed": policy["telegram"],
                "dashboard_allowed": policy["dashboard"],
                "policy_snapshot": json.dumps(
                    policy_snapshot
                ),
                "user_id": simulated_by_user_id,
                "username": simulated_by_username
            }
        )

        saved_record = result.mappings().one()

    return {
        "simulation_id": saved_record["id"],
        "severity": normalized_severity,
        "priority": policy["priority"],
        "simulation_mode": "DRY-RUN",
        "delivery_performed": False,
        "message": "Simulation completed. No notifications were sent.",
        "channels": channels,
        "created_at": saved_record["created_at"]
    }


def get_notification_simulation_history(limit=50):

    if not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError(
            "History limit must be between 1 and 200."
        )

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT
                    id,
                    severity,
                    priority,
                    email_allowed,
                    telegram_allowed,
                    dashboard_allowed,
                    policy_snapshot,
                    simulation_mode,
                    simulated_by_username,
                    created_at
                FROM notification_simulation_history
                ORDER BY created_at DESC, id DESC
                LIMIT :limit
            """),
            {
                "limit": limit
            }
        )

        return [
            dict(row)
            for row in result.mappings().all()
        ]
