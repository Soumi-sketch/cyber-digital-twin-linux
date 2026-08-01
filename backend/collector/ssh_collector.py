import re
import subprocess

from backend.database import engine
from sqlalchemy import text


def get_ssh_logs():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            "sshd",
            "--since",
            "10 minutes ago",
            "--no-pager"
        ],
        capture_output=True,
        text=True
    )

    return result.stdout.splitlines()


def parse_ssh_event(line):

    if "Failed password" in line:

        match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\S+)",
            line
        )

        if match:
            username = match.group(1)
            source_ip = match.group(2)

            return {
                "event_type": "FAILED_LOGIN",
                "username": username,
                "source_ip": source_ip,
                "message": line
            }

    elif "Accepted password" in line:

        match = re.search(
            r"Accepted password for (\S+) from (\S+)",
            line
        )

        if match:
            username = match.group(1)
            source_ip = match.group(2)

            return {
                "event_type": "SUCCESSFUL_LOGIN",
                "username": username,
                "source_ip": source_ip,
                "message": line
            }

    elif "Invalid user" in line:

        match = re.search(
            r"Invalid user (\S+) from (\S+)",
            line
        )

        if match:
            username = match.group(1)
            source_ip = match.group(2)

            return {
                "event_type": "INVALID_USER",
                "username": username,
                "source_ip": source_ip,
                "message": line
            }

    return None


def save_ssh_event(event):

    with engine.begin() as connection:

        connection.execute(
            text("""
                INSERT INTO ssh_events
                (
                    event_type,
                    username,
                    source_ip,
                    message
                )
                VALUES
                (
                    :event_type,
                    :username,
                    :source_ip,
                    :message
                )
            """),
            event
        )


def collect_ssh_events():

    logs = get_ssh_logs()

    events_found = 0

    for line in logs:

        event = parse_ssh_event(line)

        if event:

            save_ssh_event(event)

            print("SSH EVENT:", event)

            events_found += 1

    print(
        f"SSH collection complete. "
        f"{events_found} event(s) stored."
    )


if __name__ == "__main__":
    collect_ssh_events()
