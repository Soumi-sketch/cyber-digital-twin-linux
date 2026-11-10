# ============================================================
# AI SECURITY RESPONSE EXECUTION API
# ============================================================

from sqlalchemy import text

from backend.database import engine


# ============================================================
# DELIVERY HEALTH CONFIGURATION
# ============================================================

PENDING_OVERDUE_MINUTES = 10
REPEATED_FAILURE_ATTEMPTS = 3


# ============================================================
# DELIVERY HEALTH MONITOR
# ============================================================

def get_delivery_health():

    with engine.connect() as connection:

        # ----------------------------------------------------
        # INCIDENT DELIVERY SUMMARY
        # ----------------------------------------------------

        summary_result = connection.execute(
            text("""
                SELECT
                    COUNT(*) AS total_records,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'SENT'
                    ) AS sent,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'FAILED'
                    ) AS failed,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'PENDING'
                    ) AS pending,

                    COALESCE(
                        SUM(attempt_count),
                        0
                    ) AS total_attempts,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'PENDING'
                        AND last_attempt_at <
                            CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                    ) AS overdue,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'FAILED'
                        AND attempt_count >= 3
                    ) AS repeated_failures,

                    COUNT(*) FILTER (
                        WHERE severity = 'CRITICAL'
                        AND delivery_status = 'PENDING'
                        AND last_attempt_at <
                            CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                    ) AS critical_overdue

                FROM incident_notification_log
            """)
        )

        summary = dict(
            summary_result.mappings().one()
        )

        sent = int(summary["sent"])
        failed = int(summary["failed"])
        pending = int(summary["pending"])

        completed = sent + failed

        success_rate = (
            round((sent / completed) * 100, 2)
            if completed else None
        )

        failure_rate = (
            round((failed / completed) * 100, 2)
            if completed else None
        )

        # ----------------------------------------------------
        # EMAIL CHANNEL STATISTICS
        # ----------------------------------------------------

        channel_result = connection.execute(
            text("""
                SELECT
                    notification_channel,

                    COUNT(*) AS total,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'SENT'
                    ) AS sent,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'FAILED'
                    ) AS failed,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'PENDING'
                    ) AS pending,

                    COALESCE(
                        SUM(attempt_count),
                        0
                    ) AS total_attempts,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'PENDING'
                        AND last_attempt_at <
                            CURRENT_TIMESTAMP - INTERVAL '10 minutes'
                    ) AS overdue,

                    COUNT(*) FILTER (
                        WHERE delivery_status = 'FAILED'
                        AND attempt_count >= 3
                    ) AS repeated_failures

                FROM incident_notification_log

                GROUP BY notification_channel

                ORDER BY notification_channel
            """)
        )

        channel_rows = [
            dict(row)
            for row in channel_result.mappings().all()
        ]

        channels = {}

        for channel in channel_rows:

            name = channel["notification_channel"]

            channel_sent = int(channel["sent"])
            channel_failed = int(channel["failed"])
            channel_pending = int(channel["pending"])

            channel_completed = (
                channel_sent + channel_failed
            )

            if int(channel["total"]) == 0:
                health = "INSUFFICIENT_DATA"

            elif (
                int(channel["overdue"]) > 0
                or int(channel["repeated_failures"]) > 0
                or channel_failed > 0
            ):
                health = "DEGRADED"

            else:
                health = "HEALTHY"

            channels[name] = {
                "health": health,
                "total": int(channel["total"]),
                "sent": channel_sent,
                "failed": channel_failed,
                "pending": channel_pending,
                "total_attempts": int(
                    channel["total_attempts"]
                ),
                "overdue": int(channel["overdue"]),
                "repeated_failures": int(
                    channel["repeated_failures"]
                ),
                "success_rate": (
                    round(
                        channel_sent / channel_completed * 100,
                        2
                    )
                    if channel_completed else None
                )
            }

        # ----------------------------------------------------
        # HISTORICAL EVENT NOTIFICATION COUNTS
        # ----------------------------------------------------

        event_result = connection.execute(
            text("""
                SELECT
                    notification_channel,
                    COUNT(*) AS successful_records

                FROM notification_log

                GROUP BY notification_channel
            """)
        )

        event_history = {
            row["notification_channel"]: int(
                row["successful_records"]
            )
            for row in event_result.mappings().all()
        }

        # ----------------------------------------------------
        # CHANNELS WITHOUT INCIDENT DELIVERY TRACKING
        # ----------------------------------------------------

        for name in ("email", "telegram"):

            if name not in channels:

                channels[name] = {
                    "health": "INSUFFICIENT_DATA",
                    "total": 0,
                    "sent": 0,
                    "failed": 0,
                    "pending": 0,
                    "total_attempts": 0,
                    "overdue": 0,
                    "repeated_failures": 0,
                    "success_rate": None
                }

        # ----------------------------------------------------
        # OVERALL HEALTH CLASSIFICATION
        # ----------------------------------------------------

        if (
            int(summary["critical_overdue"]) > 0
            or int(summary["repeated_failures"]) > 0
        ):
            overall_health = "CRITICAL"

        elif (
            failed > 0
            or int(summary["overdue"]) > 0
        ):
            overall_health = "DEGRADED"

        else:
            overall_health = "HEALTHY"

        # ----------------------------------------------------
        # FINAL RESPONSE
        # ----------------------------------------------------

        return {
            "overall_health": overall_health,

            "summary": {
                "total_records": int(
                    summary["total_records"]
                ),
                "total_attempts": int(
                    summary["total_attempts"]
                ),
                "sent": sent,
                "failed": failed,
                "pending": pending,
                "overdue": int(summary["overdue"]),
                "repeated_failures": int(
                    summary["repeated_failures"]
                ),
                "success_rate": success_rate,
                "failure_rate": failure_rate
            },

            "channels": channels,

            "event_history": event_history,

            "monitoring_policy": {
                "pending_overdue_minutes":
                    PENDING_OVERDUE_MINUTES,
                "repeated_failure_attempts":
                    REPEATED_FAILURE_ATTEMPTS
            },

            "data_scope": (
                "Incident delivery attempts are monitored "
                "using incident_notification_log. "
                "notification_log contains successful "
                "event-level records only."
            )
        }
