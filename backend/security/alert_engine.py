from datetime import datetime, timedelta

from sqlalchemy import text

from backend.database import engine
from backend.security.risk_engine import analyze_ssh_events


def generate_security_alerts():

    events = analyze_ssh_events()

    alerts = []

    for event in events:

        score = event["risk_score"]

        # Ignore LOW-risk events
        if score < 50:
            continue

        # Determine alert
        if score >= 80:
            alert_level = "CRITICAL"

        elif score >= 50:
            alert_level = "HIGH"

        else:
            continue

        # Determine reason
        if event["event_type"] == "FAILED_LOGIN":

            reason = (
                f"Repeated failed SSH login attempt "
                f"from {event['source_ip']}"
            )

        elif event["event_type"] == "INVALID_USER":

            reason = (
                f"Invalid SSH user attempt "
                f"from {event['source_ip']}"
            )

        else:

            reason = "Suspicious SSH activity detected"

        alerts.append({
            "event_id": event["id"],
            "alert_level": alert_level,
            "risk_score": score,
            "event_type": event["event_type"],
            "username": event["username"],
            "source_ip": event["source_ip"],
            "reason": reason,
            "event_time": event["event_time"]
        })

    return alerts


if __name__ == "__main__":

    alerts = generate_security_alerts()

    print("\n========== SECURITY ALERTS ==========\n")

    if not alerts:
        print("No HIGH or CRITICAL security alerts.")

    else:

        for alert in alerts:

            print(
                f"🚨 {alert['alert_level']} | "
                f"score={alert['risk_score']} | "
                f"type={alert['event_type']} | "
                f"user={alert['username']} | "
                f"ip={alert['source_ip']} | "
                f"{alert['reason']}"
            )

    print("\n=====================================\n")
