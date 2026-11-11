import logging
from datetime import datetime, timezone

from sqlalchemy import text

from backend.database import engine
from backend.config.hosts import HOSTS
from backend.collector.remote_collector import create_ssh_client


logger = logging.getLogger("cyber_process_service")

MAX_PROCESSES = 500


def ensure_process_service_tables():
    """Create process and service inventory tables."""

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS process_inventory (
                id BIGSERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                pid INTEGER NOT NULL,
                ppid INTEGER,
                username VARCHAR(255),
                process_name VARCHAR(255) NOT NULL,
                cpu_percent FLOAT,
                memory_percent FLOAT,
                elapsed_seconds BIGINT,
                captured_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_process_inventory_host_time
            ON process_inventory(hostname, captured_at DESC)
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS service_inventory (
                id BIGSERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                unit_name VARCHAR(255) NOT NULL,
                load_state VARCHAR(50),
                active_state VARCHAR(50),
                sub_state VARCHAR(50),
                description TEXT,
                captured_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """))

        conn.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_service_inventory_host_time
            ON service_inventory(hostname, captured_at DESC)
        """))


def get_monitored_host(hostname):
    for host in HOSTS:
        if host["name"] == hostname:
            return host

    raise ValueError(f"Unknown monitored host: {hostname}")


def execute_remote(client, command, timeout=30):
    """Execute a remote command and check its exit status."""

    _, stdout, stderr = client.exec_command(
        command,
        timeout=timeout
    )

    output = stdout.read().decode(errors="replace")
    error = stderr.read().decode(errors="replace")
    status = stdout.channel.recv_exit_status()

    if status != 0:
        raise RuntimeError(
            f"Remote command failed (exit {status}): {error[:300]}"
        )

    return output


def collect_remote_processes(client):
    """
    Collect process metadata without command-line arguments.
    The result is limited to the 500 highest-CPU processes.
    """

    command = (
        "ps -eo pid=,ppid=,user=,comm=,"
        "pcpu=,pmem=,etimes= --sort=-pcpu "
        f"| head -n {MAX_PROCESSES}"
    )

    output = execute_remote(client, command)
    processes = []

    for line in output.splitlines():
        fields = line.split(None, 6)

        if len(fields) != 7:
            continue

        # Exclude the inventory command itself.
        if fields[3] == "ps":
            continue

        try:
            processes.append({
                "pid": int(fields[0]),
                "ppid": int(fields[1]),
                "username": fields[2],
                "process_name": fields[3],
                "cpu_percent": float(fields[4]),
                "memory_percent": float(fields[5]),
                "elapsed_seconds": int(fields[6])
            })
        except (ValueError, TypeError):
            logger.warning("Skipping malformed process record")

    return processes


def collect_remote_services(client):
    """Collect all systemd service units and their states."""

    command = (
        "systemctl list-units --type=service --all "
        "--no-legend --no-pager --plain --full"
    )

    output = execute_remote(client, command)
    services = []

    for line in output.splitlines():
        fields = line.split(None, 4)

        if len(fields) < 4:
            continue

        services.append({
            "unit_name": fields[0],
            "load_state": fields[1],
            "active_state": fields[2],
            "sub_state": fields[3],
            "description": fields[4] if len(fields) == 5 else ""
        })

    return services


def save_inventory(hostname, processes, services):
    """Save one timestamped inventory collection."""

    with engine.begin() as conn:
        for process in processes:
            conn.execute(text("""
                INSERT INTO process_inventory (
                    hostname,
                    pid,
                    ppid,
                    username,
                    process_name,
                    cpu_percent,
                    memory_percent,
                    elapsed_seconds
                )
                VALUES (
                    :hostname,
                    :pid,
                    :ppid,
                    :username,
                    :process_name,
                    :cpu_percent,
                    :memory_percent,
                    :elapsed_seconds
                )
            """), {
                "hostname": hostname,
                **process
            })

        for service in services:
            conn.execute(text("""
                INSERT INTO service_inventory (
                    hostname,
                    unit_name,
                    load_state,
                    active_state,
                    sub_state,
                    description
                )
                VALUES (
                    :hostname,
                    :unit_name,
                    :load_state,
                    :active_state,
                    :sub_state,
                    :description
                )
            """), {
                "hostname": hostname,
                **service
            })

    return {
        "hostname": hostname,
        "processes_saved": len(processes),
        "services_saved": len(services),
        "captured_at": datetime.now(timezone.utc).isoformat()
    }


def collect_host_inventory(hostname):
    """Collect and persist process and service inventory for one host."""

    ensure_process_service_tables()

    host = get_monitored_host(hostname)
    client = create_ssh_client(host)

    try:
        processes = collect_remote_processes(client)
        services = collect_remote_services(client)
    finally:
        client.close()

    return save_inventory(
        hostname,
        processes,
        services
    )


# ============================================================
# PHASE 25 - PERSISTENT DETECTION AND SERVICE MONITORING
# ============================================================

from backend.security.process_detection import detect_suspicious_processes


def ensure_phase25_tables():
    ensure_process_service_tables()

    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS process_detections (
                id BIGSERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                pid INTEGER NOT NULL,
                process_name VARCHAR(255) NOT NULL,
                username VARCHAR(255),
                severity VARCHAR(30) NOT NULL,
                risk_score INTEGER NOT NULL,
                category VARCHAR(100),
                reason TEXT,
                first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                occurrences INTEGER DEFAULT 1,
                status VARCHAR(30) DEFAULT 'OPEN',
                UNIQUE(hostname, pid, process_name, category)
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS service_state_history (
                id BIGSERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                unit_name VARCHAR(255) NOT NULL,
                previous_state VARCHAR(100),
                current_state VARCHAR(100),
                change_type VARCHAR(50) NOT NULL,
                captured_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS service_unit_baseline (
                id BIGSERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                unit_name VARCHAR(255) NOT NULL,
                unit_state VARCHAR(50),
                first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(hostname, unit_name)
            )
        """))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS process_service_alerts (
                id BIGSERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL,
                alert_type VARCHAR(80) NOT NULL,
                severity VARCHAR(30) NOT NULL,
                risk_score INTEGER NOT NULL,
                title VARCHAR(255) NOT NULL,
                details TEXT,
                created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
            )
        """))


def save_process_detections(hostname, findings):
    saved = 0

    with engine.begin() as conn:
        for item in findings:
            result = conn.execute(text("""
                INSERT INTO process_detections (
                    hostname, pid, process_name, username,
                    severity, risk_score, category, reason
                )
                VALUES (
                    :hostname, :pid, :process_name, :username,
                    :severity, :risk_score, :category, :reason
                )
                ON CONFLICT (hostname, pid, process_name, category)
                DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    occurrences = process_detections.occurrences + 1
                RETURNING id
            """), item)

            detection_id = result.scalar()

            conn.execute(text("""
                INSERT INTO process_service_alerts (
                    hostname, alert_type, severity, risk_score,
                    title, details
                )
                SELECT
                    :hostname, 'SUSPICIOUS_PROCESS', :severity,
                    :risk_score, :title, :details
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM process_service_alerts
                    WHERE hostname = :hostname
                      AND alert_type = 'SUSPICIOUS_PROCESS'
                      AND title = :title
                      AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
                )
            """), {
                "hostname": hostname,
                "severity": item["severity"],
                "risk_score": item["risk_score"],
                "title": f'{item["process_name"]} (PID {item["pid"]})',
                "details": item["reason"]
            })

            saved += 1

    return saved


def collect_service_unit_files(client):
    """Inventory installed systemd service unit files and their enablement."""

    output = execute_remote(
        client,
        "systemctl list-unit-files --type=service --no-legend --no-pager"
    )

    units = []

    for line in output.splitlines():
        fields = line.split()

        if len(fields) < 2 or not fields[0].endswith(".service"):
            continue

        units.append({
            "unit_name": fields[0],
            "unit_state": fields[1]
        })

    return units


def compare_service_units(hostname, units):
    changes = []
    suspicious_names = (
        "xmrig", "kinsing", "kdevtmpfsi", "cryptominer",
        "reverse-shell", "backdoor"
    )

    with engine.begin() as conn:
        baseline_exists = conn.execute(text("""
            SELECT EXISTS (
                SELECT 1 FROM service_unit_baseline
                WHERE hostname = :hostname
            )
        """), {"hostname": hostname}).scalar()

        for unit in units:
            previous = conn.execute(text("""
                SELECT unit_state
                FROM service_unit_baseline
                WHERE hostname = :hostname
                  AND unit_name = :unit_name
            """), {
                "hostname": hostname,
                "unit_name": unit["unit_name"]
            }).scalar()

            current = unit["unit_state"]

            if previous is None:
                if baseline_exists:
                    change_type = "NEW_UNIT"

                    conn.execute(text("""
                        INSERT INTO service_state_history (
                            hostname, unit_name, previous_state,
                            current_state, change_type
                        )
                        VALUES (
                            :hostname, :unit_name, 'NOT_PRESENT',
                            :current, 'NEW_UNIT'
                        )
                    """), {
                        "hostname": hostname,
                        "unit_name": unit["unit_name"],
                        "current": current
                    })

                    conn.execute(text("""
                        INSERT INTO process_service_alerts (
                            hostname, alert_type, severity, risk_score,
                            title, details
                        )
                        VALUES (
                            :hostname, 'NEW_SERVICE_UNIT',
                            'HIGH', 80, :title, :details
                        )
                    """), {
                        "hostname": hostname,
                        "title": unit["unit_name"],
                        "details": "A systemd service unit appeared after the established baseline."
                    })

                    changes.append({
                        "unit_name": unit["unit_name"],
                        "previous_state": "NOT_PRESENT",
                        "current_state": current,
                        "change_type": "NEW_UNIT"
                    })

                conn.execute(text("""
                    INSERT INTO service_unit_baseline
                        (hostname, unit_name, unit_state)
                    VALUES (:hostname, :unit_name, :unit_state)
                    ON CONFLICT (hostname, unit_name)
                    DO UPDATE SET
                        unit_state = EXCLUDED.unit_state,
                        last_seen = CURRENT_TIMESTAMP
                """), {
                    "hostname": hostname,
                    **unit
                })
                change_type = "BASELINE"
            else:
                change_type = None

                if previous != current:
                    change_type = "STATE_CHANGED"

                    conn.execute(text("""
                        INSERT INTO service_state_history (
                            hostname, unit_name, previous_state,
                            current_state, change_type
                        )
                        VALUES (
                            :hostname, :unit_name, :previous,
                            :current, :change_type
                        )
                    """), {
                        "hostname": hostname,
                        "unit_name": unit["unit_name"],
                        "previous": previous,
                        "current": current,
                        "change_type": change_type
                    })

                    conn.execute(text("""
                        INSERT INTO process_service_alerts (
                            hostname, alert_type, severity, risk_score,
                            title, details
                        )
                        VALUES (
                            :hostname, 'SERVICE_STATE_CHANGE',
                            'MEDIUM', 55, :title, :details
                        )
                    """), {
                        "hostname": hostname,
                        "title": unit["unit_name"],
                        "details": f"Service state changed from {previous} to {current}"
                    })

                    changes.append({
                        "unit_name": unit["unit_name"],
                        "previous_state": previous,
                        "current_state": current,
                        "change_type": "STATE_CHANGED"
                    })

                conn.execute(text("""
                    UPDATE service_unit_baseline
                    SET unit_state = :unit_state,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE hostname = :hostname
                      AND unit_name = :unit_name
                """), {
                    "hostname": hostname,
                    **unit
                })

            name = unit["unit_name"].lower()

            if any(indicator in name for indicator in suspicious_names):
                conn.execute(text("""
                    INSERT INTO process_service_alerts (
                        hostname, alert_type, severity, risk_score,
                        title, details
                    )
                    SELECT
                        :hostname, 'SUSPICIOUS_SERVICE',
                        'HIGH', 80, :title, :details
                    WHERE NOT EXISTS (
                        SELECT 1 FROM process_service_alerts
                        WHERE hostname = :hostname
                          AND alert_type = 'SUSPICIOUS_SERVICE'
                          AND title = :title
                          AND created_at > CURRENT_TIMESTAMP - INTERVAL '1 hour'
                    )
                """), {
                    "hostname": hostname,
                    "title": unit["unit_name"],
                    "details": "Service name matches a configured persistence indicator"
                })

                changes.append({
                    "unit_name": unit["unit_name"],
                    "change_type": "SUSPICIOUS_NAME"
                })

    return changes


def monitor_host_process_services(hostname, client):
    """Run one process/service monitoring cycle using an existing SSH client."""

    ensure_phase25_tables()

    processes = collect_remote_processes(client)
    services = collect_remote_services(client)
    unit_files = collect_service_unit_files(client)

    inventory = save_inventory(hostname, processes, services)

    findings = detect_suspicious_processes(processes, hostname)
    detections_saved = save_process_detections(hostname, findings)

    service_changes = compare_service_units(hostname, unit_files)

    return {
        "hostname": hostname,
        "processes_collected": len(processes),
        "services_collected": len(services),
        "unit_files_collected": len(unit_files),
        "detections": len(findings),
        "detections_saved": detections_saved,
        "service_changes": service_changes,
        "captured_at": inventory["captured_at"]
    }


def get_process_detections(limit=100):
    ensure_phase25_tables()

    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, hostname, pid, process_name, username,
                   severity, risk_score, category, reason,
                   first_seen, last_seen, occurrences, status
            FROM process_detections
            ORDER BY last_seen DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_service_changes(limit=100):
    ensure_phase25_tables()

    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, hostname, unit_name, previous_state,
                   current_state, change_type, captured_at
            FROM service_state_history
            ORDER BY captured_at DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_process_service_alerts(limit=100):
    ensure_phase25_tables()

    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, hostname, alert_type, severity,
                   risk_score, title, details, created_at
            FROM process_service_alerts
            ORDER BY created_at DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_process_service_summary():
    ensure_phase25_tables()

    with engine.begin() as conn:
        processes = conn.execute(text("""
            SELECT COUNT(*) FROM process_inventory
        """)).scalar()

        services = conn.execute(text("""
            SELECT COUNT(*) FROM service_inventory
        """)).scalar()

        detections = conn.execute(text("""
            SELECT COUNT(*) FROM process_detections
            WHERE status = 'OPEN'
        """)).scalar()

        alerts = conn.execute(text("""
            SELECT COUNT(*) FROM process_service_alerts
            WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
        """)).scalar()

        changes = conn.execute(text("""
            SELECT COUNT(*) FROM service_state_history
            WHERE captured_at > CURRENT_TIMESTAMP - INTERVAL '24 hours'
        """)).scalar()

    return {
        "process_inventory_records": processes,
        "service_inventory_records": services,
        "open_process_detections": detections,
        "alerts_last_24_hours": alerts,
        "service_changes_last_24_hours": changes
    }
