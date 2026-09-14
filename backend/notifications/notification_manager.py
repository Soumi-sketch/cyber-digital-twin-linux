from sqlalchemy import text

from backend.database import engine

from backend.notifications.email_service import (
    send_email_notification
)

from backend.notifications.telegram_service import (
    send_telegram_notification
)


def notification_exists(
    event_id,
    channel
):

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT 1
                FROM notification_log
                WHERE event_id = :event_id
                  AND notification_channel = :channel
                LIMIT 1
            """),
            {
                "event_id": event_id,
                "channel": channel
            }
        )

        return result.first() is not None


def save_notification(
    alert,
    channel
):

    with engine.begin() as connection:

        connection.execute(
            text("""
                INSERT INTO notification_log
                (
                    event_id,
                    notification_channel,
                    alert_level,
                    risk_score,
                    source_ip,
                    event_type
                )
                VALUES
                (
                    :event_id,
                    :channel,
                    :alert_level,
                    :risk_score,
                    :source_ip,
                    :event_type
                )
                ON CONFLICT
                (
                    event_id,
                    notification_channel
                )
                DO NOTHING
            """),
            {
                "event_id": alert["event_id"],
                "channel": channel,
                "alert_level": alert["alert_level"],
                "risk_score": alert["risk_score"],
                "source_ip": alert["source_ip"],
                "event_type": alert["event_type"]
            }
        )


def build_notification_message(
    alert
):

    return (
        "🚨 CYBER DIGITAL TWIN SECURITY ALERT\n\n"
        f"Alert Level: {alert['alert_level']}\n"
        f"Risk Score: {alert['risk_score']}\n"
        f"Event Type: {alert['event_type']}\n"
        f"Username: {alert['username']}\n"
        f"Source IP: {alert['source_ip']}\n"
        f"Reason: {alert['reason']}\n"
        f"Event Time: {alert['event_time']}\n"
    )


def send_alert_notifications(
    alert
):

    message = build_notification_message(
        alert
    )


    results = {}


    if not notification_exists(
        alert["event_id"],
        "email"
    ):

        email_sent = send_email_notification(
            subject=(
                "🚨 Cyber Digital Twin "
                f"{alert['alert_level']} Security Alert"
            ),
            message=message
        )

        results["email"] = email_sent


        if email_sent:

            save_notification(
                alert,
                "email"
            )

    else:

        print(
            f"📧 Email already sent for "
            f"event {alert['event_id']}."
        )

        results["email"] = "duplicate"


    if not notification_exists(
        alert["event_id"],
        "telegram"
    ):

        telegram_sent = (
            send_telegram_notification(
                message
            )
        )

        results["telegram"] = telegram_sent


        if telegram_sent:

            save_notification(
                alert,
                "telegram"
            )

    else:

        print(
            f"📱 Telegram already sent for "
            f"event {alert['event_id']}."
        )

        results["telegram"] = "duplicate"


    return results
