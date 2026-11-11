from sqlalchemy import text
from backend.database import engine


def predict_attack_patterns(days=30):

    if not 1 <= days <= 90:
        raise ValueError("days must be between 1 and 90")

    with engine.connect() as conn:

        rows = conn.execute(text("""
            SELECT
                source_ip,
                event_type,
                COUNT(*) AS total,
                COUNT(DISTINCT username) AS unique_usernames,
                MIN(event_time) AS first_seen,
                MAX(event_time) AS last_seen
            FROM ssh_events
            WHERE event_time >=
                CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
              AND event_type IN ('FAILED_LOGIN', 'INVALID_USER')
            GROUP BY source_ip, event_type
            ORDER BY total DESC
        """), {"days": days}).mappings().all()

    total_events = sum(row["total"] for row in rows)

    source_summary = {}

    for row in rows:

        ip = row["source_ip"] or "UNKNOWN"

        if ip not in source_summary:
            source_summary[ip] = {
                "source_ip": ip,
                "failed_logins": 0,
                "invalid_users": 0,
                "unique_usernames": 0,
                "total_suspicious_events": 0,
                "first_seen": None,
                "last_seen": None
            }

        item = source_summary[ip]

        if row["event_type"] == "FAILED_LOGIN":
            item["failed_logins"] += row["total"]

        elif row["event_type"] == "INVALID_USER":
            item["invalid_users"] += row["total"]

        item["unique_usernames"] += row["unique_usernames"]
        item["total_suspicious_events"] += row["total"]

        if item["first_seen"] is None or row["first_seen"] < item["first_seen"]:
            item["first_seen"] = row["first_seen"]

        if item["last_seen"] is None or row["last_seen"] > item["last_seen"]:
            item["last_seen"] = row["last_seen"]

    predictions = []

    for item in source_summary.values():

        failed = item["failed_logins"]
        invalid = item["invalid_users"]
        total = item["total_suspicious_events"]

        if invalid > failed:
            pattern = "INVALID_USER_ENUMERATION"
        elif failed >= 5 and item["unique_usernames"] >= 3:
            pattern = "POSSIBLE_BRUTE_FORCE"
        elif failed >= 3:
            pattern = "REPEATED_FAILED_LOGIN"
        else:
            pattern = "LOW_VOLUME_SUSPICIOUS_ACTIVITY"

        frequency = round(
            (total / total_events) * 100, 2
        ) if total_events else 0

        predictions.append({
            **item,
            "dominant_pattern": pattern,
            "historical_frequency_percent": frequency,
            "recurrence_estimate": (
                "HIGH" if frequency >= 50
                else "MEDIUM" if frequency >= 20
                else "LOW"
            )
        })

    predictions.sort(
        key=lambda item: item["total_suspicious_events"],
        reverse=True
    )

    return {
        "analysis_period_days": days,
        "total_suspicious_events": total_events,
        "sources_analyzed": len(predictions),
        "predicted_attack_patterns": predictions,
        "method": "Historical SSH event frequency and source-based pattern classification",
        "limitation": "Recurrence estimates are heuristic indicators, not validated probabilities or proof of future attacks."
    }

