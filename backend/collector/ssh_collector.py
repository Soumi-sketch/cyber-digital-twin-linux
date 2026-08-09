import os
import re
import paramiko

from dotenv import load_dotenv

from backend.database import engine
from sqlalchemy import text

load_dotenv(override=True)

HOST = os.getenv("HOST")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")


def get_ssh_logs(client):

    command = (
        "journalctl -u sshd "
        "--since '10 minutes ago' "
        "--no-pager"
    )

    stdin, stdout, stderr = client.exec_command(command)

    logs = stdout.read().decode().splitlines()

    error = stderr.read().decode().strip()

    if error:
        print("SSH LOG ERROR:", error)

    return logs


def parse_ssh_event(line):

    # INVALID USER
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
                "message": line
            }

    # FAILED LOGIN
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
                "message": line
            }

    # SUCCESSFUL LOGIN
    if "Accepted password" in line:

        match = re.search(
            r"Accepted password for (\S+) from (\S+) port (\d+)",
            line
        )

        if match:

            return {
                "event_type": "SUCCESSFUL_LOGIN",
                "username": match.group(1),
                "source_ip": match.group(2),
                "source_port": match.group(3),
                "message": line
            }

    return None


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
            {
                "event_type": event["event_type"],
                "username": event["username"],
                "source_ip": event["source_ip"],
                "message": event["message"]
            }
        )


def collect_ssh_events(client):

    logs = get_ssh_logs(client)

    events_found = 0

    # Get the source port of the SSH connection
    # used by the Cyber Digital Twin collector.
    monitoring_port = None

    try:

        transport = client.get_transport()

        if transport and transport.sock:

            monitoring_port = transport.sock.getsockname()[1]

    except Exception:

        monitoring_port = None

    for line in logs:

        event = parse_ssh_event(line)

        if not event:
            continue

        # Ignore ONLY the successful SSH login created
        # by the Cyber Digital Twin monitoring connection.
        #
        # Do NOT ignore all twin-monitor logins.
        if (
            event["event_type"] == "SUCCESSFUL_LOGIN"
            and event["username"] == USERNAME
            and monitoring_port is not None
            and f"port {monitoring_port} " in event["message"]
        ):
            continue

        # Prevent duplicate journal messages from
        # being inserted into PostgreSQL.
        if event_exists(event["message"]):
            continue

        save_ssh_event(event)

        print("SSH EVENT:", event)

        events_found += 1

    print(
        f"SSH collection complete. "
        f"{events_found} new event(s) stored."
    )


if __name__ == "__main__":

    client = paramiko.SSHClient()

    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    client.connect(
        hostname=HOST,
        username=USERNAME,
        password=PASSWORD
    )

    try:

        collect_ssh_events(client)

    finally:

        client.close()
