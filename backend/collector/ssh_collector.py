import os
import re
import paramiko

from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import text

from backend.database import engine

load_dotenv()

HOST = os.getenv("HOST")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")


# ============================================================
# CREATE SSH CONNECTION
# ============================================================

def create_ssh_client():

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    client.connect(
        hostname=HOST,
        username=USERNAME,
        password=PASSWORD,
        timeout=10
    )

    return client


# ============================================================
# GET SSH LOGS
# ============================================================

def get_ssh_logs(client):

    command = (
        "journalctl "
        "--since '1 minute ago' "
        "--no-pager"
    )

    stdin, stdout, stderr = client.exec_command(command)

    logs = stdout.read().decode().splitlines()

    error = stderr.read().decode().strip()

    if error:
        print("SSH LOG ERROR:", error)

    return logs


# ============================================================
# PARSE JOURNAL TIMESTAMP
# ============================================================

def parse_event_time(line):

    match = re.match(
        r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})",
        line
    )

    if not match:
        return None

    month = match.group(1)
    day = match.group(2)
    time_part = match.group(3)

    current_year = datetime.now().year

    try:

        return datetime.strptime(
            f"{current_year} {month} {day} {time_part}",
            "%Y %b %d %H:%M:%S"
        )

    except ValueError:

        return None


# ============================================================
# PARSE SSH EVENT
# ============================================================

def parse_ssh_event(line):

    event_time = parse_event_time(line)

    # --------------------------------------------------------
    # INVALID USER
    # --------------------------------------------------------

    if "Invalid user" in line:

        match = re.search(
            r"Invalid user (\S+) from (\S+)",
            line
        )

        if match:

            return {
                "event_type": "INVALID_USER",
                "username": match.group(1),
                "source_ip": match.group(2),
                "message": line,
                "event_time": event_time
            }

    # --------------------------------------------------------
    # FAILED LOGIN
    # --------------------------------------------------------

    if "Failed password" in line:

        match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\S+)",
            line
        )

        if match:

            return {
                "event_type": "FAILED_LOGIN",
                "username": match.group(1),
                "source_ip": match.group(2),
                "message": line,
                "event_time": event_time
            }

    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

    if "Accepted password" in line:

        match = re.search(
            r"Accepted password for (\S+) from (\S+)",
            line
        )

        if match:

            return {
                "event_type": "SUCCESSFUL_LOGIN",
                "username": match.group(1),
                "source_ip": match.group(2),
                "message": line,
                "event_time": event_time
            }

    return None


# ============================================================
# CHECK DUPLICATE EVENT
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
# SAVE EVENT
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
                    message,
                    event_time
                )
                VALUES
                (
                    :event_type,
                    :username,
                    :source_ip,
                    :message,
                    COALESCE(:event_time, CURRENT_TIMESTAMP)
                )
            """),
            event
        )


# ============================================================
# COLLECT SSH EVENTS
# ============================================================

def collect_ssh_events(client):

    logs = get_ssh_logs(client)

    events_found = 0

    for line in logs:

        event = parse_ssh_event(line)

        if not event:
            continue

        # Every SSH user is monitored.

        if event_exists(event["message"]):
            continue

        save_ssh_event(event)

        print(
            f"🔐 SSH EVENT: "
            f"{event['event_type']} | "
            f"user={event['username']} | "
            f"ip={event['source_ip']}"
        )

        events_found += 1

    print(
        f"SSH collection complete. "
        f"{events_found} new event(s) stored."
    )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    client = None

    try:

        client = create_ssh_client()

        collect_ssh_events(client)

    finally:

        if client:
            client.close()
