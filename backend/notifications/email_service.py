import os
import smtplib

from email.message import EmailMessage

from dotenv import load_dotenv


load_dotenv(
    override=True
)


def send_email_notification(
    subject,
    message
):

    enabled = os.getenv(
        "EMAIL_ENABLED",
        "false"
    ).lower() == "true"


    if not enabled:

        print(
            "📧 Email notifications are disabled."
        )

        return False


    smtp_host = os.getenv(
        "SMTP_HOST"
    )

    smtp_port = int(
        os.getenv(
            "SMTP_PORT",
            "587"
        )
    )

    smtp_username = os.getenv(
        "SMTP_USERNAME"
    )

    smtp_password = os.getenv(
        "SMTP_PASSWORD"
    )

    sender = os.getenv(
        "ALERT_EMAIL_FROM"
    )

    recipient = os.getenv(
        "ALERT_EMAIL_TO"
    )

    use_tls = os.getenv(
        "SMTP_USE_TLS",
        "true"
    ).lower() == "true"


    required = {
        "SMTP_HOST": smtp_host,
        "SMTP_USERNAME": smtp_username,
        "SMTP_PASSWORD": smtp_password,
        "ALERT_EMAIL_FROM": sender,
        "ALERT_EMAIL_TO": recipient
    }


    missing = [
        key
        for key, value in required.items()
        if not value
    ]


    if missing:

        raise ValueError(
            "Missing email configuration: "
            + ", ".join(missing)
        )


    email = EmailMessage()

    email["Subject"] = subject

    email["From"] = sender

    email["To"] = recipient

    email.set_content(
        message
    )


    try:

        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=10
        ) as server:

            if use_tls:

                server.starttls()


            server.login(
                smtp_username,
                smtp_password
            )


            server.send_message(
                email
            )


        print(
            "📧 Email notification sent successfully."
        )

        return True


    except Exception as error:

        print(
            f"❌ Email notification failed: "
            f"{error}"
        )

        return False
