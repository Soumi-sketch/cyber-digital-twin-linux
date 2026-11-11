import hashlib
import logging
import shlex
from datetime import datetime, timezone

from sqlalchemy import text

from backend.database import engine
from backend.config.hosts import HOSTS
from backend.collector.remote_collector import create_ssh_client


logger = logging.getLogger("cyber_fim")

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

MONITORED_DIRECTORIES = [
    "/etc/ssh",
    "/etc/sudoers.d",
    "/etc/cron.d",
]

DIRECTORY_HASH = hashlib.sha256(b"FIM_DIRECTORY").hexdigest()


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

        # Stable event identity also deduplicates events with NULL new_hash.
        conn.execute(text("""
            ALTER TABLE fim_events
            ADD COLUMN IF NOT EXISTS event_key VARCHAR(64)
        """))

        conn.execute(text("""
            UPDATE fim_events
            SET event_key = md5(
                id::text || '|' ||
                event_type || '|' ||
                COALESCE(old_hash, '') || '|' ||
                COALESCE(new_hash, '')
            )
            WHERE event_key IS NULL
        """))

        conn.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS uq_fim_event_key
            ON fim_events(hostname, file_path, event_type, event_key)
        """))


def get_host(hostname):
    for host in HOSTS:
        if host["name"] == hostname:
            return host

    raise ValueError("Unknown monitored host")


def _remote_command(client, command):
    _, stdout, stderr = client.exec_command(command, timeout=60)

    output = stdout.read()
    error = stderr.read()
    status = stdout.channel.recv_exit_status()

    return output, error, status


def collect_hashes(client):
    results = {}

    # Monitor explicitly configured critical files.
    for path in MONITORED_FILES:
        quoted = shlex.quote(path)

        command = (
            "if test -f " + quoted +
            "; then sha256sum -- " + quoted +
            "; elif test -e " + quoted +
            "; then echo NOT_REGULAR_FILE; "
            "else echo FILE_MISSING; fi"
        )

        output, error, status = _remote_command(client, command)
        output = output.decode(errors="replace").strip()
        error = error.decode(errors="replace").strip()

        if status != 0:
            results[path] = {"error": error or "Remote hash command failed"}
        elif output == "FILE_MISSING":
            results[path] = None
        elif output == "NOT_REGULAR_FILE":
            results[path] = {"error": "Path is not a regular file"}
        elif output:
            digest = output.split()[0]

            if len(digest) == 64:
                results[path] = digest
            else:
                results[path] = {"error": "Invalid SHA-256 output"}
        else:
            results[path] = {"error": error or "Unable to read file"}

    # Discover all directories and regular files under monitored roots.
    roots = " ".join(shlex.quote(p) for p in MONITORED_DIRECTORIES)

    directory_command = (
        "for d in " + roots + "; do "
        'if test -d "$d"; then '
        'find "$d" -type d -print0 || exit 1; '
        "fi; done"
    )

    directory_output, directory_error, directory_status = (
        _remote_command(client, directory_command)
    )

    if directory_status != 0:
        raise RuntimeError(
            "Directory discovery failed: " +
            directory_error.decode(errors="replace")
        )

    for raw_path in directory_output.split(b"\0"):
        if not raw_path:
            continue

        path = raw_path.decode(errors="replace")
        results[path] = DIRECTORY_HASH

    file_command = (
        "for d in " + roots + "; do "
        'if test -d "$d"; then '
        'find "$d" -type f -exec sha256sum --zero -- {} + || exit 1; '
        "fi; done"
    )

    file_output, file_error, file_status = (
        _remote_command(client, file_command)
    )

    if file_status != 0:
        raise RuntimeError(
            "Directory file hashing failed: " +
            file_error.decode(errors="replace")
        )

    # sha256sum --zero separates records with NUL, preserving unusual names.
    for record in file_output.split(b"\0"):
        if not record:
            continue

        if len(record) < 67:
            raise RuntimeError("Invalid sha256sum record received")

        digest = record[:64].decode(errors="strict")
        path = record[66:].decode(errors="replace")

        if len(digest) != 64:
            raise RuntimeError("Invalid SHA-256 digest received")

        results[path] = digest

    return results


def create_baseline(hostname, username="admin"):
    ensure_fim_tables()

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
        "baseline_objects_saved": saved,
        "skipped_files": skipped
    }


def _event_key(event_type, old_hash, new_hash):
    raw = (
        event_type + "|" +
        (old_hash or "") + "|" +
        (new_hash or "")
    )

    return hashlib.sha256(raw.encode()).hexdigest()


def _dispatch_fim_alert(host, event):
    from backend.security.alert_engine import process_security_alert

    severity = event["severity"]
    risk_score = 95 if severity == "CRITICAL" else 70

    alert = {
        "event_id": event["event_id"],
        "alert_level": severity,
        "risk_score": risk_score,
        "event_type": "FIM_" + event["event"],
        "username": "file-integrity-monitor",
        "source_ip": host.get("host", "unknown"),
        "reason": (
            f"{severity} file integrity event: "
            f"{event['event']} detected on {event['file']}"
        ),
        "event_time": datetime.now(timezone.utc).isoformat()
    }

    return process_security_alert(alert)


def scan_integrity(hostname, dispatch_alerts=True):
    ensure_fim_tables()

    host = get_host(hostname)
    client = create_ssh_client(host)

    try:
        current = collect_hashes(client)
    finally:
        client.close()

    events = []

    with engine.begin() as conn:
        baseline = conn.execute(text("""
            SELECT file_path, sha256
            FROM fim_baselines
            WHERE hostname = :hostname
        """), {"hostname": hostname}).mappings().all()

        if not baseline:
            raise ValueError("No baseline exists. Create a baseline first.")

        baseline_map = {
            item["file_path"]: item["sha256"]
            for item in baseline
        }

        # A failed hash must never be interpreted as a deletion.
        errors = [
            path for path, value in current.items()
            if isinstance(value, dict)
        ]

        if errors:
            raise RuntimeError(
                "Incomplete FIM scan; refusing to report deletions. "
                f"Unreadable paths: {errors[:10]}"
            )

        changes = []

        # Existing baseline objects: detect modification and deletion.
        for path, old_hash in baseline_map.items():
            new_hash = current.get(path)

            if new_hash is None:
                event_type = "DELETED"
                severity = "CRITICAL"

            elif new_hash != old_hash:
                event_type = "MODIFIED"
                severity = "HIGH"

            else:
                continue

            changes.append({
                "file": path,
                "event": event_type,
                "severity": severity,
                "old_hash": old_hash,
                "new_hash": new_hash
            })

        # Newly discovered files and directories.
        for path, new_hash in current.items():
            if path in baseline_map:
                continue

            if new_hash is None:
                continue

            changes.append({
                "file": path,
                "event": "CREATED",
                "severity": "HIGH",
                "old_hash": None,
                "new_hash": new_hash
            })

        # Persist events without changing the original baseline.
        for event in changes:
            event_key = _event_key(
                event["event"],
                event["old_hash"],
                event["new_hash"]
            )

            result = conn.execute(text("""
                INSERT INTO fim_events
                    (hostname, file_path, event_type, old_hash,
                     new_hash, severity, event_key)
                VALUES
                    (:hostname, :path, :event, :old_hash,
                     :new_hash, :severity, :event_key)
                ON CONFLICT DO NOTHING
                RETURNING id
            """), {
                "hostname": hostname,
                "path": event["file"],
                "event": event["event"],
                "old_hash": event["old_hash"],
                "new_hash": event["new_hash"],
                "severity": event["severity"],
                "event_key": event_key
            })

            inserted = result.fetchone()

            if inserted:
                event["event_id"] = inserted[0]
                events.append(event)

    # Dispatch only newly inserted events, outside the DB transaction.
    if dispatch_alerts:
        for event in events:
            try:
                result = _dispatch_fim_alert(host, event)
                event["alert_status"] = result.get("status", "processed")
            except Exception:
                logger.exception(
                    "FIM alert dispatch failed for %s",
                    event["file"]
                )
                event["alert_status"] = "DISPATCH_FAILED"

    return {
        "hostname": hostname,
        "files_checked": len(baseline_map),
        "objects_checked": len(current),
        "changes_detected": len(events),
        "events": events,
        "baseline_automatically_changed": False,
        "alerts_dispatched": (
            sum(1 for e in events if e.get("alert_status") == "processed")
            if dispatch_alerts else 0
        )
    }


def get_fim_events(limit=100):
    ensure_fim_tables()

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
    ensure_fim_tables()

    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT hostname, file_path, sha256, updated_at, updated_by
            FROM fim_baselines
            ORDER BY hostname, file_path
        """)).mappings().all()

    return [dict(row) for row in rows]
