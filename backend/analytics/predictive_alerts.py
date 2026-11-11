from backend.analytics.predictive_risk import predict_security_risk
from backend.analytics.anomaly_forecast import forecast_metric_anomalies
from backend.analytics.attack_pattern_predictor import predict_attack_patterns


def generate_predictive_alerts(days=30):

    alerts = []

    risk = predict_security_risk(days=days)

    risk_score = risk.get("predictive_risk", {}).get("score", 0)
    risk_level = risk.get("predictive_risk", {}).get("level", "LOW")

    if risk_score >= 80:
        alerts.append({
            "alert_type": "PREDICTIVE_SECURITY_RISK",
            "severity": "CRITICAL",
            "risk_score": risk_score,
            "message": "Critical security risk is predicted from historical SSH activity."
        })

    elif risk_score >= 50:
        alerts.append({
            "alert_type": "PREDICTIVE_SECURITY_RISK",
            "severity": "HIGH",
            "risk_score": risk_score,
            "message": "Elevated security risk is predicted from historical SSH activity."
        })

    elif risk_score >= 20:
        alerts.append({
            "alert_type": "PREDICTIVE_SECURITY_RISK",
            "severity": "MEDIUM",
            "risk_score": risk_score,
            "message": "Moderate security risk is predicted from historical SSH activity."
        })

    anomaly_data = forecast_metric_anomalies()

    for metric, result in anomaly_data.get("metrics", {}).items():

        if result.get("predicted_anomaly"):

            alerts.append({
                "alert_type": "PREDICTED_INFRASTRUCTURE_ANOMALY",
                "severity": "HIGH",
                "metric": metric,
                "predicted_value": result.get(
                    "predicted_next_observation_average"
                ),
                "message": (
                    f"A possible {metric} anomaly is predicted "
                    "from historical infrastructure trends."
                )
            })

    attack_data = predict_attack_patterns(days=days)

    for pattern in attack_data.get(
        "predicted_attack_patterns", []
    ):

        if (
            pattern.get("recurrence_estimate") == "HIGH"
            and pattern.get("total_suspicious_events", 0) >= 5
        ):

            alerts.append({
                "alert_type": "PREDICTED_ATTACK_PATTERN",
                "severity": "MEDIUM",
                "source_ip": pattern.get("source_ip"),
                "attack_pattern": pattern.get("dominant_pattern"),
                "historical_events": pattern.get(
                    "total_suspicious_events"
                ),
                "message": (
                    "A recurring suspicious SSH activity pattern "
                    "was identified in historical data."
                )
            })

    return {
        "analysis_period_days": days,
        "total_predictive_alerts": len(alerts),
        "predictive_alerts": alerts,
        "notification_status": "NOT_SENT",
        "method": "Rule-based predictive alert correlation",
        "limitation": (
            "Alerts are heuristic forecasts, not proof of future attacks."
        )
    }

