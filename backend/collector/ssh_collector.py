import re
import subprocess

from backend.database import engine
from sqlalchemy import text


# ============================================================
# GET SSH LOGS
# ============================================================

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


# ============================================================
# PARSE SSH EVENT
# ============================================================

def parse_ssh_event(line):

    # --------------------------------------------------------
    # FAILED LOGIN
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # INVALID USER
    # --------------------------------------------------------

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


# ============================================================
# CHECK IF EVENT ALREADY EXISTS
# ============================================================

def event_exists(message):

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT 1
                FROM ssh_events
                WHERE message = :message
                LIMIT 1
            """),
            {
                "message": message
            }
        )

        return result.first() is not None


# ============================================================
# SAVE SSH EVENT
# ============================================================

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


# ============================================================
# COLLECT SSH EVENTS
# ============================================================

def collect_ssh_events():

    logs = get_ssh_logs()

    events_found = 0

    for line in logs:

        event = parse_ssh_event(line)

        if event:

            # Do not store the same journal entry twice
            if event_exists(event["message"]):
                continue

            save_ssh_event(event)

            print("SSH EVENT:", event)

            events_found += 1

    print(
        f"SSH collection complete. "
        f"{events_found} new event(s) stored."
    )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    collect_ssh_events()
