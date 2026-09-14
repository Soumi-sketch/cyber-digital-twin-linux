import os

import requests

from dotenv import load_dotenv


load_dotenv(
    dotenv_path="/root/cyber-digital-twin/.env",
    override=True
)


def send_telegram_notification(
    message
):

    enabled = os.getenv(
        "TELEGRAM_ENABLED",
        "false"
    ).lower() == "true"


    if not enabled:

        print(
            "📱 Telegram notifications are disabled."
        )

        return False


    bot_token = os.getenv(
        "TELEGRAM_BOT_TOKEN"
    )

    chat_id = os.getenv(
        "TELEGRAM_CHAT_ID"
    )


    if not bot_token:

        raise ValueError(
            "Missing TELEGRAM_BOT_TOKEN."
        )


    if not chat_id:

        raise ValueError(
            "Missing TELEGRAM_CHAT_ID."
        )


    url = (
        f"https://api.telegram.org/bot"
        f"{bot_token}/sendMessage"
    )


    payload = {
        "chat_id": chat_id,
        "text": message
    }


    try:

        response = requests.post(
            url,
            json=payload,
            timeout=10
        )

        response.raise_for_status()


        data = response.json()


        if not data.get("ok"):

            raise RuntimeError(
                data.get(
                    "description",
                    "Telegram API request failed."
                )
            )


        print(
            "📱 Telegram notification sent successfully."
        )

        return True


    except Exception as error:

        print(
            f"❌ Telegram notification failed: "
            f"{error}"
        )

        return False
