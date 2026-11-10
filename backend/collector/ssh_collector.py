import os
import re
import paramiko

from datetime import datetime
from zoneinfo import ZoneInfo
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
        "-o short-iso-precise "
        "--no-pager"
    )

    stdin, stdout, stderr = client.exec_command(
        command,
        timeout=10
    )

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
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))",
        line
    )

    if not match:
        return None

    try:

        parsed_time = datetime.fromisoformat(
            match.group(1).replace("Z", "+00:00")
        )

        return parsed_time.astimezone(
            ZoneInfo("Asia/Kolkata")
        ).replace(tzinfo=None)

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

def event_exists(message, target_hostname, target_ip):

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT 1
                FROM ssh_events
                WHERE message = :message
                  AND target_hostname = :target_hostname
                  AND target_ip = :target_ip
                LIMIT 1
            """),
            {
                "message": message,
                "target_hostname": target_hostname,
                "target_ip": target_ip
            }
        )

        return result.first() is not None
# ============================================================
# SAVE EVENT
# ============================================================


def save_ssh_event(event, target_hostname, target_ip):

    with engine.begin() as connection:

        # Lock the specific message and target.
        # The lock is automatically released at transaction end.

        connection.execute(
            text("""
                SELECT pg_advisory_xact_lock(
                    hashtextextended(
                        :lock_key,
                        0
                    )
                )
            """),
            {
                "lock_key": (
                    f"{target_hostname}|"
                    f"{target_ip}|"
                    f"{event['message']}"
                )
            }
        )

        # Check again while holding the lock.

        existing = connection.execute(
            text("""
                SELECT id
                FROM ssh_events
                WHERE message = :message
                  AND (
                      :event_time IS NULL
                      OR event_time = :event_time
                  )
                  AND target_hostname = :target_hostname
                  AND target_ip = :target_ip
                LIMIT 1
            """),
            {
                "message": event["message"],
                "event_time": event["event_time"],
                "target_hostname": target_hostname,
                "target_ip": target_ip
            }
        ).first()

        if existing:
            return None

        # Insert only when the event does not exist.

        result = connection.execute(
            text("""
                INSERT INTO ssh_events
                (
                    event_type,
                    username,
                    source_ip,
                    message,
                    event_time,
                    target_hostname,
                    target_ip
                )
                VALUES
                (
                    :event_type,
                    :username,
                    :source_ip,
                    :message,
                    COALESCE(:event_time, CURRENT_TIMESTAMP),
                    :target_hostname,
                    :target_ip
                )
                RETURNING id
            """),
            {
                **event,
                "target_hostname": target_hostname,
                "target_ip": target_ip
            }
        )

        return result.scalar_one()

# ============================================================
# COLLECT SSH EVENTS
# ============================================================


def collect_ssh_events(client, target_hostname, target_ip):

    logs = get_ssh_logs(client)

    events_found = 0
    new_event_ids = []

    for line in logs:

        event = parse_ssh_event(line)

        if not event:
            continue

        # Atomic duplicate check and insertion.

        event_id = save_ssh_event(
            event,
            target_hostname,
            target_ip
        )

        # Skip if the event already exists.

        if event_id is None:
            continue

        new_event_ids.append(event_id)

        print(
            f"🔐 SSH EVENT: "
            f"{event['event_type']} | "
            f"user={event['username']} | "
            f"source={event['source_ip']} | "
            f"target={target_hostname} ({target_ip}) | "
            f"id={event_id}"
        )

        events_found += 1

    print(
        f"SSH collection complete. "
        f"{events_found} new event(s) stored."
    )

    return new_event_ids

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
