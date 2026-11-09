from backend.security.risk_engine import analyze_ssh_events

from backend.security.incident_engine import (
    detect_ssh_incidents
)

from backend.ai.security_decision_engine import (
    generate_security_decision
)

from backend.notifications.notification_manager import (
    send_alert_notifications,
    send_incident_email_notification
)

from backend.notifications.notification_policy import (
    should_send_notification
)

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


def process_security_alert(
    alert
):

    if not alert:

        return {
            "status": "ignored",
            "reason": "Empty alert"
        }


    if alert["alert_level"] not in (
        "HIGH",
        "CRITICAL"
    ):

        return {
            "status": "ignored",
            "reason": "Alert level below notification threshold"
        }


    results = send_alert_notifications(
        alert
    )


    return {
        "status": "processed",
        "event_id": alert["event_id"],
        "notification_results": results
    }


def process_new_ssh_events(event_ids):

    if not event_ids:
        return []

    events = analyze_ssh_events(event_ids=event_ids)

    results = []

    for event in events:

        score = event["risk_score"]

        if score < 50:
            continue

        if score >= 80:
            alert_level = "CRITICAL"
        else:
            alert_level = "HIGH"

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

        alert = {
            "event_id": event["id"],
            "alert_level": alert_level,
            "risk_score": score,
            "event_type": event["event_type"],
            "username": event["username"],
            "source_ip": event["source_ip"],
            "reason": reason,
            "event_time": event["event_time"]
        }

        try:
            result = process_security_alert(alert)

        except Exception as error:
            result = {
                "status": "error",
                "event_id": event["id"],
                "reason": str(error)
            }

        results.append(result)

    # ----------------------------------------
    # PROCESS CORRELATED SECURITY INCIDENTS
    # ----------------------------------------

    try:

        incidents = detect_ssh_incidents()

        new_event_set = set(event_ids)

        for incident in incidents:

            # Only process incidents containing new SSH events.
            related_event_ids = set(
                incident.get("event_ids", [])
            )

            if not new_event_set.intersection(
                related_event_ids
            ):
                continue

            # Enforce severity-based email notification policy.
            if not should_send_notification(
                incident["severity"],
                "email"
            ):
                continue

            decision = generate_security_decision(
                incident
            )

            notification_result = (
                send_incident_email_notification(
                    incident,
                    decision
                )
            )

            results.append({
                "status": "incident_notification_processed",
                "incident_id": incident["incident_id"],
                "severity": incident["severity"],
                "priority": decision["priority"],
                "email_result": notification_result
            })

    except Exception as error:

        results.append({
            "status": "incident_notification_error",
            "reason": str(error)
        })

    return results
