
# ============================================================
# SEVERITY-BASED NOTIFICATION POLICY ENGINE
# ============================================================

# This module decides which notification channels
# are permitted for each incident severity.

# It does NOT send notifications.


NOTIFICATION_POLICIES = {

    "LOW": {
        "email": False,
        "telegram": False,
        "dashboard": True,
        "priority": "P4"
    },

    "MEDIUM": {
        "email": False,
        "telegram": False,
        "dashboard": True,
        "priority": "P3"
    },

    "HIGH": {
        "email": True,
        "telegram": False,
        "dashboard": True,
        "priority": "P2"
    },

    "CRITICAL": {
        "email": True,
        "telegram": True,
        "dashboard": True,
        "priority": "P1"
    }

}


def get_notification_policy(severity):

    normalized_severity = str(
        severity
    ).strip().upper()

    policy = NOTIFICATION_POLICIES.get(
        normalized_severity
    )

    if policy is None:

        raise ValueError(
            f"Unsupported incident severity: "
            f"{normalized_severity}"
        )

    return {
        "severity": normalized_severity,
        **policy
    }


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

    if normalized_channel not in (
        "email",
        "telegram",
        "dashboard"
    ):

        raise ValueError(
            f"Unsupported notification channel: "
            f"{normalized_channel}"
        )

    return policy[normalized_channel]

