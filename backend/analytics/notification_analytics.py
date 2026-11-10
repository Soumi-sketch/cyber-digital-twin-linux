from sqlalchemy import text

from backend.database import engine


ALLOWED_PERIODS = {
    "daily": "day",
    "weekly": "week",
    "monthly": "month"
}


def get_notification_analytics(
    days: int = 90,
    period: str = "daily"
):

    if days < 1 or days > 365:
        raise ValueError("Days must be between 1 and 365")

    if period not in ALLOWED_PERIODS:
        raise ValueError("Invalid analytics period")

    db_period = ALLOWED_PERIODS[period]

    with engine.connect() as connection:

        # ==================================================
        # 1. EVENT NOTIFICATION SUMMARY
        # ==================================================

        event_summary_query = text("""
            SELECT
                COUNT(*) AS total_recorded_successes
            FROM notification_log
            WHERE sent_at >=
                NOW() - (:days * INTERVAL '1 day')
        """)

        event_summary = dict(
            connection.execute(
                event_summary_query,
                {"days": days}
            ).mappings().one()
        )

        # ==================================================
        # 2. EVENT NOTIFICATIONS BY CHANNEL
        # ==================================================

        event_channel_query = text("""
            SELECT
                notification_channel,
                COUNT(*) AS recorded_successes
            FROM notification_log
            WHERE sent_at >=
                NOW() - (:days * INTERVAL '1 day')
            GROUP BY notification_channel
            ORDER BY notification_channel
        """)

        event_channels = [
            dict(row)
            for row in connection.execute(
                event_channel_query,
                {"days": days}
            ).mappings()
        ]

        # ==================================================
        # 3. EVENT NOTIFICATIONS BY SEVERITY
        # ==================================================

        event_severity_query = text("""
            SELECT
                alert_level,
                COUNT(*) AS recorded_successes
            FROM notification_log
            WHERE sent_at >=
                NOW() - (:days * INTERVAL '1 day')
            GROUP BY alert_level
            ORDER BY alert_level
        """)

        event_severity = [
            dict(row)
            for row in connection.execute(
                event_severity_query,
                {"days": days}
            ).mappings()
        ]

        # ==================================================
        # 4. EVENT NOTIFICATION TREND
        # ==================================================

        event_trend_query = text("""
            SELECT
                DATE_TRUNC(
                    :period,
                    sent_at
                ) AS period_start,

                notification_channel,

                COUNT(*) AS recorded_successes

            FROM notification_log

            WHERE sent_at >=
                NOW() - (:days * INTERVAL '1 day')

            GROUP BY
                DATE_TRUNC(:period, sent_at),
                notification_channel

            ORDER BY period_start
        """)

        event_trend = [
            dict(row)
            for row in connection.execute(
                event_trend_query,
                {
                    "period": db_period,
                    "days": days
                }
            ).mappings()
        ]

        # ==================================================
        # 5. INCIDENT DELIVERY SUMMARY
        # ==================================================

        incident_summary_query = text("""
            SELECT
                COUNT(*) AS total_records,

                COALESCE(
                    SUM(
                        CASE
                            WHEN delivery_status = 'SENT'
                            THEN 1 ELSE 0
                        END
                    ), 0
                ) AS sent,

                COALESCE(
                    SUM(
                        CASE
                            WHEN delivery_status = 'FAILED'
                            THEN 1 ELSE 0
                        END
                    ), 0
                ) AS failed,

                COALESCE(
                    SUM(
                        CASE
                            WHEN delivery_status = 'PENDING'
                            THEN 1 ELSE 0
                        END
                    ), 0
                ) AS pending,

                COALESCE(
                    SUM(attempt_count), 0
                ) AS total_attempts

            FROM incident_notification_log

            WHERE created_at >=
                NOW() - (:days * INTERVAL '1 day')
        """)

        incident_summary = dict(
            connection.execute(
                incident_summary_query,
                {"days": days}
            ).mappings().one()
        )

        # ==================================================
        # 6. INCIDENT DELIVERY BY CHANNEL
        # ==================================================

        incident_channel_query = text("""
            SELECT
                notification_channel,

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
                    SUM(attempt_count), 0
                ) AS total_attempts

            FROM incident_notification_log

            WHERE created_at >=
                NOW() - (:days * INTERVAL '1 day')

            GROUP BY notification_channel

            ORDER BY notification_channel
        """)

        incident_channels = [
            dict(row)
            for row in connection.execute(
                incident_channel_query,
                {"days": days}
            ).mappings()
        ]

        # ==================================================
        # 7. INCIDENT DELIVERY BY SEVERITY
        # ==================================================

        incident_severity_query = text("""
            SELECT
                severity,

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
                    SUM(attempt_count), 0
                ) AS total_attempts

            FROM incident_notification_log

            WHERE created_at >=
                NOW() - (:days * INTERVAL '1 day')

            GROUP BY severity

            ORDER BY severity
        """)

        incident_severity = [
            dict(row)
            for row in connection.execute(
                incident_severity_query,
                {"days": days}
            ).mappings()
        ]

        # ==================================================
        # 8. INCIDENT DELIVERY TREND
        # ==================================================

        incident_trend_query = text("""
            SELECT
                DATE_TRUNC(
                    :period,
                    created_at
                ) AS period_start,

                notification_channel,

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
                    SUM(attempt_count), 0
                ) AS total_attempts

            FROM incident_notification_log

            WHERE created_at >=
                NOW() - (:days * INTERVAL '1 day')

            GROUP BY
                DATE_TRUNC(:period, created_at),
                notification_channel

            ORDER BY period_start
        """)

        incident_trend = [
            dict(row)
            for row in connection.execute(
                incident_trend_query,
                {
                    "period": db_period,
                    "days": days
                }
            ).mappings()
        ]

    # ======================================================
    # 9. FINAL RESPONSE
    # ======================================================

    return {
        "period": period,
        "days": days,

        "event_notifications": {
            "summary": event_summary,
            "by_channel": event_channels,
            "by_severity": event_severity,
            "trend": event_trend
        },

        "incident_deliveries": {
            "summary": incident_summary,
            "by_channel": incident_channels,
            "by_severity": incident_severity,
            "trend": incident_trend
        },

        "data_scope": {
            "event_notifications": (
                "Successful event-level records only. "
                "Failed event-level attempts are not stored "
                "in notification_log."
            ),

            "incident_deliveries": (
                "Incident delivery records with status "
                "and attempt counts."
            ),

            "success_rate_note": (
                "Event-level success records and incident-level "
                "delivery attempts must not be combined."
            )
        }
    }
