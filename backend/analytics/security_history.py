from sqlalchemy import text
from backend.database import engine


ALLOWED_PERIODS = {
    "daily": "day",
    "weekly": "week",
    "monthly": "month"
}


def get_security_history(days=30, period="daily"):

    if not isinstance(days, int) or not 1 <= days <= 90:
        raise ValueError("Days must be between 1 and 90")

    if period not in ALLOWED_PERIODS:
        raise ValueError("Invalid period")

    db_period = ALLOWED_PERIODS[period]

    with engine.connect() as connection:

        # 1. Overall SSH event summary
        summary = [
            dict(row)
            for row in connection.execute(text("""
                SELECT
                    event_type,
                    COUNT(*) AS total
                FROM ssh_events
                WHERE event_time >=
                    CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                GROUP BY event_type
                ORDER BY total DESC
            """), {"days": days}).mappings()
        ]

        # 2. Daily/weekly/monthly suspicious-event trend
        trend = [
            dict(row)
            for row in connection.execute(text("""
                SELECT
                    DATE_TRUNC(:period, event_time) AS period_start,
                    COUNT(*) AS suspicious_events,
                    COUNT(*) FILTER (
                        WHERE event_type = 'FAILED_LOGIN'
                    ) AS failed_logins,
                    COUNT(*) FILTER (
                        WHERE event_type = 'INVALID_USER'
                    ) AS invalid_users
                FROM ssh_events
                WHERE event_time >=
                    CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                  AND event_type IN ('FAILED_LOGIN', 'INVALID_USER')
                GROUP BY DATE_TRUNC(:period, event_time)
                ORDER BY period_start
            """), {
                "days": days,
                "period": db_period
            }).mappings()
        ]

        # 3. Top suspicious source IP addresses
        top_sources = [
            dict(row)
            for row in connection.execute(text("""
                SELECT
                    source_ip,
                    COUNT(*) AS suspicious_events,
                    COUNT(*) FILTER (
                        WHERE event_type = 'FAILED_LOGIN'
                    ) AS failed_logins,
                    COUNT(*) FILTER (
                        WHERE event_type = 'INVALID_USER'
                    ) AS invalid_users,
                    MAX(event_time) AS last_seen
                FROM ssh_events
                WHERE event_time >=
                    CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                  AND event_type IN ('FAILED_LOGIN', 'INVALID_USER')
                  AND source_ip IS NOT NULL
                  AND source_ip <> ''
                GROUP BY source_ip
                ORDER BY suspicious_events DESC
                LIMIT 10
            """), {"days": days}).mappings()
        ]

        # 4. Total event counters
        totals = dict(
            connection.execute(text("""
                SELECT
                    COUNT(*) AS total_events,
                    COUNT(*) FILTER (
                        WHERE event_type = 'FAILED_LOGIN'
                    ) AS failed_logins,
                    COUNT(*) FILTER (
                        WHERE event_type = 'INVALID_USER'
                    ) AS invalid_users,
                    COUNT(*) FILTER (
                        WHERE event_type = 'SUCCESSFUL_LOGIN'
                    ) AS successful_logins
                FROM ssh_events
                WHERE event_time >=
                    CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
            """), {"days": days}).mappings().one()
        )

    return {
        "period_days": days,
        "grouping": period,
        "summary_by_event_type": summary,
        "event_totals": totals,
        "suspicious_event_trend": trend,
        "top_suspicious_sources": top_sources
    }

def get_ssh_attack_trends(days=30):

    if not isinstance(days, int) or not 1 <= days <= 90:
        raise ValueError("Days must be between 1 and 90")

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT
                COUNT(*) FILTER (
                    WHERE event_time >= CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                      AND event_type IN ('FAILED_LOGIN', 'INVALID_USER')
                ) AS current_suspicious,

                COUNT(*) FILTER (
                    WHERE event_time >= CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')
                      AND event_time < CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                      AND event_type IN ('FAILED_LOGIN', 'INVALID_USER')
                ) AS previous_suspicious,

                COUNT(*) FILTER (
                    WHERE event_time >= CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                      AND event_type = 'FAILED_LOGIN'
                ) AS current_failed,

                COUNT(*) FILTER (
                    WHERE event_time >= CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')
                      AND event_time < CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                      AND event_type = 'FAILED_LOGIN'
                ) AS previous_failed,

                COUNT(*) FILTER (
                    WHERE event_time >= CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                      AND event_type = 'INVALID_USER'
                ) AS current_invalid,

                COUNT(*) FILTER (
                    WHERE event_time >= CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')
                      AND event_time < CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                      AND event_type = 'INVALID_USER'
                ) AS previous_invalid

            FROM ssh_events
            WHERE event_time >= CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')
        """), {"days": days}).mappings().one()

    def analyse(current, previous):

        if previous == 0:
            return {
                "current": current,
                "previous": previous,
                "change_percent": None,
                "direction": "NEW_ACTIVITY" if current > 0 else "STABLE"
            }

        change = round(
            ((current - previous) / previous) * 100, 2
        )

        if change > 10:
            direction = "INCREASING"
        elif change < -10:
            direction = "DECREASING"
        else:
            direction = "STABLE"

        return {
            "current": current,
            "previous": previous,
            "change_percent": change,
            "direction": direction
        }

    return {
        "comparison_period_days": days,
        "total_suspicious_events": analyse(
            result["current_suspicious"],
            result["previous_suspicious"]
        ),
        "failed_login_trend": analyse(
            result["current_failed"],
            result["previous_failed"]
        ),
        "invalid_user_trend": analyse(
            result["current_invalid"],
            result["previous_invalid"]
        )
    }
