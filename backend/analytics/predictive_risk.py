from sqlalchemy import text

from backend.database import engine


def predict_security_risk(days=30):

    if not isinstance(days, int) or not 1 <= days <= 90:
        raise ValueError("Days must be between 1 and 90")

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT

                COUNT(*) FILTER (
                    WHERE event_time >=
                        CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                    AND event_type = 'FAILED_LOGIN'
                ) AS current_failed,

                COUNT(*) FILTER (
                    WHERE event_time >=
                        CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                    AND event_type = 'INVALID_USER'
                ) AS current_invalid,

                COUNT(*) FILTER (
                    WHERE event_time >=
                        CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')
                    AND event_time <
                        CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                    AND event_type = 'FAILED_LOGIN'
                ) AS previous_failed,

                COUNT(*) FILTER (
                    WHERE event_time >=
                        CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')
                    AND event_time <
                        CURRENT_TIMESTAMP - (:days * INTERVAL '1 day')
                    AND event_type = 'INVALID_USER'
                ) AS previous_invalid

            FROM ssh_events

            WHERE event_time >=
                CURRENT_TIMESTAMP - (:days * 2 * INTERVAL '1 day')

        """), {"days": days}).mappings().one()

    current_failed = result["current_failed"]
    current_invalid = result["current_invalid"]

    previous_failed = result["previous_failed"]
    previous_invalid = result["previous_invalid"]

    # Linear trend projection
    predicted_failed = max(
        0, current_failed + (current_failed - previous_failed)
    )

    predicted_invalid = max(
        0, current_invalid + (current_invalid - previous_invalid)
    )

    predicted_total = predicted_failed + predicted_invalid

    # Weighted predictive risk score
    raw_score = (
        predicted_failed * 2
        + predicted_invalid * 3
    )

    # Historical activity baseline prevents zero-risk assumptions
    historical_baseline = min(
        20,
        (current_failed * 0.5) + (current_invalid * 1)
    )

    predicted_score = min(
        100,
        round((raw_score * 2) + historical_baseline)
    )
    if predicted_score >= 80:
        risk_level = "CRITICAL"

    elif predicted_score >= 50:
        risk_level = "HIGH"

    elif predicted_score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "forecast_period_days": days,

        "historical_data": {
            "current_failed_logins": current_failed,
            "previous_failed_logins": previous_failed,
            "current_invalid_users": current_invalid,
            "previous_invalid_users": previous_invalid
        },

        "prediction": {
            "predicted_failed_logins": predicted_failed,
            "predicted_invalid_users": predicted_invalid,
            "predicted_suspicious_events": predicted_total
        },

        "predictive_risk": {
            "score": predicted_score,
            "level": risk_level
        },

        "method": "Linear trend projection with weighted risk scoring"
    }
