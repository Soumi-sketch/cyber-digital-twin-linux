# ============================================================
# DATABASE-BACKED NOTIFICATION POLICY ENGINE
# PHASE 21.6 - ADMIN NOTIFICATION SETTINGS
# ============================================================

from sqlalchemy import text

from backend.database import engine


# ------------------------------------------------------------
# SAFE DEFAULT PRIORITIES
# ------------------------------------------------------------

SEVERITY_PRIORITIES = {
    "LOW": "P4",
    "MEDIUM": "P3",
    "HIGH": "P2",
    "CRITICAL": "P1"
}


VALID_CHANNELS = {
    "email",
    "telegram",
    "dashboard"
}


# ------------------------------------------------------------
# GET CURRENT POLICY FROM POSTGRESQL
# ------------------------------------------------------------

def get_notification_policy(severity):

    normalized_severity = str(
        severity
    ).strip().upper()

    if normalized_severity not in SEVERITY_PRIORITIES:

        raise ValueError(
            f"Unsupported incident severity: "
            f"{normalized_severity}"
        )

    # Safe fallback:
    # External delivery is blocked if settings cannot be read.
    safe_policy = {
        "email": False,
        "telegram": False,
        "dashboard": True,
        "priority": SEVERITY_PRIORITIES[
            normalized_severity
        ]
    }

    try:

        with engine.connect() as connection:

            result = connection.execute(
                text("""
                    SELECT
                        email_enabled,
                        telegram_enabled,
                        dashboard_enabled
                    FROM notification_settings
                    WHERE severity = :severity
                """),
                {
                    "severity": normalized_severity
                }
            )

            row = result.mappings().first()

            if row is None:

                return {
                    "severity": normalized_severity,
                    **safe_policy
                }

            return {
                "severity": normalized_severity,
                "email": bool(row["email_enabled"]),
                "telegram": bool(row["telegram_enabled"]),
                "dashboard": bool(row["dashboard_enabled"]),
                "priority": SEVERITY_PRIORITIES[
                    normalized_severity
                ]
            }

    except Exception:

        # Fail closed for external delivery.
        # Preserve dashboard visibility.
        return {
            "severity": normalized_severity,
            **safe_policy
        }


# ------------------------------------------------------------
# CHECK CHANNEL PERMISSION
# ------------------------------------------------------------

def should_send_notification(
    severity,
    channel
):

    policy = get_notification_policy(
        severity
    )

    normalized_channel = str(
        channel
    ).strip().lower()

    if normalized_channel not in VALID_CHANNELS:

        raise ValueError(
            f"Unsupported notification channel: "
            f"{normalized_channel}"
        )

    return policy[normalized_channel]

