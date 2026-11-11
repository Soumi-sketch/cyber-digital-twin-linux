import hashlib
import shlex
from datetime import datetime, timezone

from sqlalchemy import text

from backend.database import engine
from backend.config.hosts import HOSTS
from backend.collector.remote_collector import create_ssh_client


MONITORED_FILES = [
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/fstab",
]

def ensure_fim_tables():
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS fim_baselines (
                id SERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                file_path TEXT NOT NULL,
                sha256 VARCHAR(64) NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by VARCHAR(255),
                UNIQUE(hostname, file_path)
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS fim_events (
                id SERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                file_path TEXT NOT NULL,
                event_type VARCHAR(30) NOT NULL,
                old_hash VARCHAR(64),
                new_hash VARCHAR(64),
                severity VARCHAR(20) NOT NULL,
                detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(hostname, file_path, event_type, new_hash)
            )
        """))


def get_host(hostname):
    for host in HOSTS:
        if host["name"] == hostname:
            return host
    raise ValueError("Unknown monitored host")


def collect_hashes(client):
    results = {}

    for path in MONITORED_FILES:
        command = (
            "if test -f " + shlex.quote(path) +
            "; then sha256sum -- " + shlex.quote(path) +
            "; else echo FILE_MISSING; fi"
        )

        _, stdout, stderr = client.exec_command(command, timeout=15)
        output = stdout.read().decode(errors="replace").strip()
        error = stderr.read().decode(errors="replace").strip()

        if output == "FILE_MISSING":
            results[path] = None
        elif output:
            results[path] = output.split()[0]
        else:
            results[path] = {"error": error or "Unable to read file"}

    return results


def create_baseline(hostname, username="admin"):
    host = get_host(hostname)
    client = create_ssh_client(host)

    try:
        hashes = collect_hashes(client)
    finally:
        client.close()

    saved = 0
    skipped = []

    with engine.begin() as conn:
        for path, digest in hashes.items():
            if not isinstance(digest, str):
                skipped.append(path)
                continue

            conn.execute(text("""
                INSERT INTO fim_baselines
                    (hostname, file_path, sha256, updated_by)
                VALUES
                    (:hostname, :path, :digest, :username)
                ON CONFLICT (hostname, file_path)
                DO UPDATE SET
                    sha256 = EXCLUDED.sha256,
                    updated_at = CURRENT_TIMESTAMP,
                    updated_by = EXCLUDED.updated_by
            """), {
                "hostname": hostname,
                "path": path,
                "digest": digest,
                "username": username
            })
            saved += 1

    return {
        "hostname": hostname,
        "baseline_files_saved": saved,
        "skipped_files": skipped
    }


def scan_integrity(hostname):
    host = get_host(hostname)
    client = create_ssh_client(host)

    try:
        current = collect_hashes(client)
    finally:
        client.close()

    with engine.begin() as conn:
        baseline = conn.execute(text("""
            SELECT file_path, sha256
            FROM fim_baselines
            WHERE hostname = :hostname
        """), {"hostname": hostname}).mappings().all()

        if not baseline:
            raise ValueError("No baseline exists. Create a baseline first.")

        events = []

        for item in baseline:
            path = item["file_path"]
            old_hash = item["sha256"]
            new_hash = current.get(path)

            if isinstance(new_hash, dict):
                continue

            if new_hash is None:
                event_type = "DELETED"
                severity = "CRITICAL"
            elif new_hash != old_hash:
                event_type = "MODIFIED"
                severity = "HIGH"
            else:
                continue

            result = conn.execute(text("""
                INSERT INTO fim_events
                    (hostname, file_path, event_type, old_hash,
                     new_hash, severity)
                VALUES
                    (:hostname, :path, :event, :old_hash,
                     :new_hash, :severity)
                ON CONFLICT (hostname, file_path, event_type, new_hash)
                DO NOTHING
                RETURNING id
            """), {
                "hostname": hostname,
                "path": path,
                "event": event_type,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "severity": severity
            })

            if result.fetchone():
                events.append({
                    "file": path,
                    "event": event_type,
                    "severity": severity
                })

    return {
        "hostname": hostname,
        "files_checked": len(baseline),
        "changes_detected": len(events),
        "events": events,
        "baseline_automatically_changed": False
    }


def get_fim_events(limit=100):
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT id, hostname, file_path, event_type,
                   old_hash, new_hash, severity, detected_at
            FROM fim_events
            ORDER BY detected_at DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_fim_baselines():
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT hostname, file_path, sha256, updated_at, updated_by
            FROM fim_baselines
            ORDER BY hostname, file_path
        """)).mappings().all()

    return [dict(row) for row in rows]
