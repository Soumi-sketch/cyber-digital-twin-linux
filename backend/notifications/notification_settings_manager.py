# ============================================================
# PHASE 21.6 - ADMIN NOTIFICATION SETTINGS MANAGER
# ============================================================

from sqlalchemy import text

from backend.database import engine


# ------------------------------------------------------------
# DEFAULT PRIORITIES
# ------------------------------------------------------------

SEVERITY_PRIORITIES = {
    "LOW": "P4",
    "MEDIUM": "P3",
    "HIGH": "P2",
    "CRITICAL": "P1"
}


# ------------------------------------------------------------
# VALIDATION
# ------------------------------------------------------------

VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
}

VALID_CHANNELS = {
    "EMAIL": "email_enabled",
    "TELEGRAM": "telegram_enabled",
    "DASHBOARD": "dashboard_enabled"
}


def normalize_severity(severity):

    normalized = str(
        severity
    ).strip().upper()

    if normalized not in VALID_SEVERITIES:

        raise ValueError(
            f"Unsupported severity: {normalized}"
        )

    return normalized


def normalize_channel(channel):

    normalized = str(
        channel
    ).strip().upper()

    if normalized not in VALID_CHANNELS:

        raise ValueError(
            f"Unsupported notification channel: {normalized}"
        )

    return normalized


# ------------------------------------------------------------
# GET ALL NOTIFICATION SETTINGS
# ------------------------------------------------------------

def get_notification_settings():

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT
                    severity,
                    email_enabled,
                    telegram_enabled,
                    dashboard_enabled,
                    updated_by_user_id,
                    created_at,
                    updated_at
                FROM notification_settings
                ORDER BY
                    CASE severity
                        WHEN 'LOW' THEN 1
                        WHEN 'MEDIUM' THEN 2
                        WHEN 'HIGH' THEN 3
                        WHEN 'CRITICAL' THEN 4
                    END
            """)
        )

        records = []

        for row in result.mappings().all():

            record = dict(row)

            record["priority"] = (
                SEVERITY_PRIORITIES[
                    record["severity"]
                ]
            )

            records.append(record)

        return records


# ------------------------------------------------------------
# GET ONE SEVERITY POLICY
# ------------------------------------------------------------

def get_notification_setting(severity):

    normalized = normalize_severity(
        severity
    )

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT
                    severity,
                    email_enabled,
                    telegram_enabled,
                    dashboard_enabled,
                    updated_by_user_id,
                    created_at,
                    updated_at
                FROM notification_settings
                WHERE severity = :severity
            """),
            {
                "severity": normalized
            }
        )

        row = result.mappings().first()

        if row is None:

            raise RuntimeError(
                f"Notification settings missing for {normalized}"
            )

        record = dict(row)

        record["priority"] = (
            SEVERITY_PRIORITIES[normalized]
        )

        return record


# ------------------------------------------------------------
# UPDATE ONE NOTIFICATION CHANNEL
# ------------------------------------------------------------

def update_notification_setting(
    severity,
    channel,
    enabled,
    changed_by_user_id,
    changed_by_username
):

    normalized_severity = normalize_severity(
        severity
    )

    normalized_channel = normalize_channel(
        channel
    )

    if not isinstance(enabled, bool):

        raise ValueError(
            "enabled must be a boolean"
        )

    if (
        not isinstance(changed_by_user_id, int)
        or isinstance(changed_by_user_id, bool)
        or changed_by_user_id <= 0
    ):

        raise ValueError(
            "A valid user ID is required"
        )

    username = str(
        changed_by_username
    ).strip()

    if not username or len(username) > 100:

        raise ValueError(
            "A valid username is required"
        )

    column = VALID_CHANNELS[
        normalized_channel
    ]

    # Critical dashboard notifications must remain enabled.
    if (
        normalized_severity == "CRITICAL"
        and normalized_channel == "DASHBOARD"
        and not enabled
    ):

        raise ValueError(
            "CRITICAL dashboard notifications cannot be disabled"
        )

    with engine.begin() as connection:

        # Lock the severity row to prevent concurrent updates.
        result = connection.execute(
            text("""
                SELECT
                    severity,
                    email_enabled,
                    telegram_enabled,
                    dashboard_enabled
                FROM notification_settings
                WHERE severity = :severity
                FOR UPDATE
            """),
            {
                "severity": normalized_severity
            }
        )

        current = result.mappings().first()

        if current is None:

            raise RuntimeError(
                f"Notification settings missing for "
                f"{normalized_severity}"
            )

        old_enabled = bool(
            current[column]
        )

        # No audit entry is necessary for an unchanged value.
        if old_enabled == enabled:

            return {
                "status": "unchanged",
                "severity": normalized_severity,
                "channel": normalized_channel,
                "enabled": enabled
            }

        # Update setting.
        connection.execute(
            text(f"""
                UPDATE notification_settings
                SET
                    {column} = :enabled,
                    updated_by_user_id = :user_id,
                    updated_at = CURRENT_TIMESTAMP
                WHERE severity = :severity
            """),
            {
                "enabled": enabled,
                "user_id": changed_by_user_id,
                "severity": normalized_severity
            }
        )

        # Record the change in the audit table.
        connection.execute(
            text("""
                INSERT INTO notification_settings_audit (
                    severity,
                    channel,
                    old_enabled,
                    new_enabled,
                    changed_by_user_id,
                    changed_by_username
                )
                VALUES (
                    :severity,
                    :channel,
                    :old_enabled,
                    :new_enabled,
                    :user_id,
                    :username
                )
            """),
            {
                "severity": normalized_severity,
                "channel": normalized_channel,
                "old_enabled": old_enabled,
                "new_enabled": enabled,
                "user_id": changed_by_user_id,
                "username": username
            }
        )

    return {
        "status": "updated",
        "severity": normalized_severity,
        "channel": normalized_channel,
        "old_enabled": old_enabled,
        "new_enabled": enabled,
        "changed_by": username
    }


# ------------------------------------------------------------
# NOTIFICATION SETTINGS AUDIT HISTORY
# ------------------------------------------------------------

def get_notification_settings_audit(limit=100):

    if (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit > 500
    ):

        raise ValueError(
            "limit must be between 1 and 500"
        )

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT
                    id,
                    severity,
                    channel,
                    old_enabled,
                    new_enabled,
                    changed_by_user_id,
                    changed_by_username,
                    changed_at
                FROM notification_settings_audit
                ORDER BY changed_at DESC, id DESC
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
