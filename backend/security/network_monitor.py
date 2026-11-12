import json
import shlex
from datetime import datetime, timezone

from sqlalchemy import text

from backend.database import engine


RETENTION_DAYS = 7

# Ports frequently associated with unauthorized remote access,
# malware listeners, exposed management APIs or insecure services.
RISKY_PORTS = {
    21: ("MEDIUM", 50, "FTP_LISTENER"),
    23: ("HIGH", 70, "TELNET_LISTENER"),
    4444: ("CRITICAL", 95, "POSSIBLE_REVERSE_SHELL"),
    5555: ("HIGH", 85, "SUSPICIOUS_REMOTE_ACCESS"),
    6667: ("HIGH", 80, "IRC_LISTENER"),
    9001: ("HIGH", 80, "SUSPICIOUS_LISTENER"),
    1080: ("MEDIUM", 55, "SOCKS_PROXY"),
    12345: ("CRITICAL", 95, "SUSPICIOUS_REMOTE_ACCESS"),
    1337: ("HIGH", 80, "SUSPICIOUS_LISTENER"),
    2375: ("CRITICAL", 95, "EXPOSED_DOCKER_API"),
    31337: ("CRITICAL", 95, "SUSPICIOUS_REMOTE_ACCESS"),
    6379: ("HIGH", 80, "REDIS_LISTENER"),
    5900: ("HIGH", 75, "VNC_LISTENER"),
    27017: ("HIGH", 80, "MONGODB_LISTENER"),
}


def ensure_phase26_tables():
    statements = [
        """
        CREATE TABLE IF NOT EXISTS network_interfaces (
            id BIGSERIAL PRIMARY KEY,
            hostname TEXT NOT NULL,
            interface_name TEXT NOT NULL,
            addresses TEXT,
            mac_address TEXT,
            state TEXT,
            mtu INTEGER,
            collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS network_listeners (
            id BIGSERIAL PRIMARY KEY,
            hostname TEXT NOT NULL,
            protocol TEXT,
            state TEXT,
            local_address TEXT,
            local_port INTEGER,
            peer_address TEXT,
            process_info TEXT,
            collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS network_connections (
            id BIGSERIAL PRIMARY KEY,
            hostname TEXT NOT NULL,
            protocol TEXT,
            state TEXT,
            local_address TEXT,
            local_port INTEGER,
            peer_address TEXT,
            peer_port INTEGER,
            process_info TEXT,
            collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS network_security_alerts (
            id BIGSERIAL PRIMARY KEY,
            hostname TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            local_address TEXT,
            local_port INTEGER,
            title TEXT NOT NULL,
            details TEXT,
            status TEXT NOT NULL DEFAULT 'OPEN',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_network_interfaces_host_time
        ON network_interfaces(hostname, collected_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_network_listeners_host_time
        ON network_listeners(hostname, collected_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_network_connections_host_time
        ON network_connections(hostname, collected_at DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_network_alerts_time
        ON network_security_alerts(created_at DESC)
        """
    ]

    with engine.begin() as conn:
        for statement in statements:
            conn.execute(text(statement))


def _run(client, command):
    stdin, stdout, stderr = client.exec_command(
        command,
        timeout=30
    )
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    status = stdout.channel.recv_exit_status()

    if status != 0:
        raise RuntimeError(
            f"Remote command failed ({status}): {error[:500]}"
        )

    return output


def _endpoint(value):
    value = value.strip()

    if value.startswith("[") and "]:" in value:
        address, port = value.rsplit(":", 1)
        address = address[1:-1]
    elif ":" in value:
        address, port = value.rsplit(":", 1)
    else:
        return value, None

    try:
        return address, int(port)
    except ValueError:
        return address, None


def collect_interfaces(client):
    raw = _run(client, "ip -j address show")
    data = json.loads(raw or "[]")

    result = []

    for item in data:
        addresses = []

        for address in item.get("addr_info", []):
            local = address.get("local")
            prefix = address.get("prefixlen")
            if local:
                addresses.append(f"{local}/{prefix}")

        result.append({
            "interface_name": item.get("ifname", "unknown"),
            "addresses": json.dumps(addresses),
            "mac_address": item.get("address"),
            "state": item.get("operstate"),
            "mtu": item.get("mtu")
        })

    return result


def _parse_ss_line(line):
    fields = shlex.split(line)

    if len(fields) < 5:
        return None

    protocol = fields[0].lower()
    state = fields[1]
    local = fields[4]
    peer = fields[5] if len(fields) > 5 else ""
    process = " ".join(fields[6:]) if len(fields) > 6 else ""

    local_address, local_port = _endpoint(local)
    peer_address, peer_port = _endpoint(peer)

    return {
        "protocol": protocol,
        "state": state,
        "local_address": local_address,
        "local_port": local_port,
        "peer_address": peer_address,
        "peer_port": peer_port,
        "process_info": process
    }


def collect_listeners(client):
    raw = _run(client, "ss -H -lntup")
    result = []

    for line in raw.splitlines():
        item = _parse_ss_line(line)
        if item:
            result.append(item)

    return result


def collect_connections(client):
    raw = _run(
        client,
        "ss -H -tunap | head -n 500"
    )

    result = []

    for line in raw.splitlines():
        item = _parse_ss_line(line)
        if item:
            result.append(item)

    return result


def detect_risky_listeners(hostname, listeners):
    findings = []

    for listener in listeners:
        port = listener.get("local_port")

        if port not in RISKY_PORTS:
            continue

        severity, score, category = RISKY_PORTS[port]
        address = listener.get("local_address") or ""
        exposed = address in ("*", "0.0.0.0", "::", "0.0.0.0/0")

        # Increase severity for risky services exposed on all interfaces.
        if exposed and severity == "MEDIUM":
            severity = "HIGH"
            score = min(score + 20, 90)

        findings.append({
            "hostname": hostname,
            "alert_type": category,
            "severity": severity,
            "risk_score": score,
            "local_address": address,
            "local_port": port,
            "title": f"Risky network listener on port {port}",
            "details": (
                f"{listener.get('protocol')} listener at "
                f"{address}:{port}; state={listener.get('state')}; "
                f"process={listener.get('process_info') or 'not reported'}"
            )
        })

    return findings


def _save_rows(conn, table, hostname, rows, columns):
    if not rows:
        return

    names = ["hostname"] + columns
    statement = text(
        f"INSERT INTO {table} ({', '.join(names)}) "
        f"VALUES ({', '.join(':' + name for name in names)})"
    )

    values = []

    for row in rows:
        values.append({
            "hostname": hostname,
            **{column: row.get(column) for column in columns}
        })

    conn.execute(statement, values)


def save_network_inventory(hostname, interfaces, listeners, connections):
    with engine.begin() as conn:
        _save_rows(
            conn,
            "network_interfaces",
            hostname,
            interfaces,
            [
                "interface_name", "addresses", "mac_address",
                "state", "mtu"
            ]
        )

        _save_rows(
            conn,
            "network_listeners",
            hostname,
            listeners,
            [
                "protocol", "state", "local_address",
                "local_port", "peer_address", "process_info"
            ]
        )

        _save_rows(
            conn,
            "network_connections",
            hostname,
            connections,
            [
                "protocol", "state", "local_address",
                "local_port", "peer_address", "peer_port",
                "process_info"
            ]
        )

        conn.execute(text("""
            DELETE FROM network_interfaces
            WHERE collected_at < NOW() - (:days * INTERVAL '1 day')
        """), {"days": RETENTION_DAYS})

        conn.execute(text("""
            DELETE FROM network_listeners
            WHERE collected_at < NOW() - (:days * INTERVAL '1 day')
        """), {"days": RETENTION_DAYS})

        conn.execute(text("""
            DELETE FROM network_connections
            WHERE collected_at < NOW() - (:days * INTERVAL '1 day')
        """), {"days": RETENTION_DAYS})


def save_network_alerts(findings):
    inserted = 0

    with engine.begin() as conn:
        for item in findings:
            exists = conn.execute(text("""
                SELECT 1
                FROM network_security_alerts
                WHERE hostname = :hostname
                  AND alert_type = :alert_type
                  AND local_port = :local_port
                  AND created_at > NOW() - INTERVAL '1 hour'
                LIMIT 1
            """), item).first()

            if exists:
                continue

            conn.execute(text("""
                INSERT INTO network_security_alerts (
                    hostname, alert_type, severity, risk_score,
                    local_address, local_port, title, details
                ) VALUES (
                    :hostname, :alert_type, :severity, :risk_score,
                    :local_address, :local_port, :title, :details
                )
            """), item)

            inserted += 1

    return inserted


def monitor_host_network(hostname, client):
    interfaces = collect_interfaces(client)
    listeners = collect_listeners(client)
    connections = collect_connections(client)

    findings = detect_risky_listeners(hostname, listeners)

    save_network_inventory(
        hostname,
        interfaces,
        listeners,
        connections
    )

    alerts_saved = save_network_alerts(findings)

    return {
        "hostname": hostname,
        "interfaces": len(interfaces),
        "listeners": len(listeners),
        "connections": len(connections),
        "findings": len(findings),
        "alerts_saved": alerts_saved
    }


def _latest_count(conn, table):
    return conn.execute(text(f"""
        WITH latest AS (
            SELECT hostname, MAX(collected_at) AS captured
            FROM {table}
            GROUP BY hostname
        )
        SELECT COUNT(*)
        FROM {table} item
        JOIN latest
          ON latest.hostname = item.hostname
         AND latest.captured = item.collected_at
    """)).scalar() or 0


def get_network_summary():
    ensure_phase26_tables()

    with engine.begin() as conn:
        interfaces = _latest_count(conn, "network_interfaces")
        listeners = _latest_count(conn, "network_listeners")
        connections = _latest_count(conn, "network_connections")

        alerts = conn.execute(text("""
            SELECT COUNT(*)
            FROM network_security_alerts
            WHERE created_at > NOW() - INTERVAL '24 hours'
        """)).scalar() or 0

        open_alerts = conn.execute(text("""
            SELECT COUNT(*)
            FROM network_security_alerts
            WHERE status = 'OPEN'
        """)).scalar() or 0

    return {
        "interface_count": interfaces,
        "listener_count": listeners,
        "connection_count": connections,
        "alerts_last_24_hours": alerts,
        "open_alerts": open_alerts
    }


def get_network_interfaces(limit=100):
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT ON (hostname, interface_name)
                hostname, interface_name, addresses,
                mac_address, state, mtu, collected_at
            FROM network_interfaces
            ORDER BY hostname, interface_name, collected_at DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_network_listeners(limit=200):
    with engine.begin() as conn:
        rows = conn.execute(text("""
            WITH latest AS (
                SELECT hostname, MAX(collected_at) AS captured
                FROM network_listeners
                GROUP BY hostname
            )
            SELECT item.*
            FROM network_listeners item
            JOIN latest
              ON latest.hostname = item.hostname
             AND latest.captured = item.collected_at
            ORDER BY item.hostname, item.local_port
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_network_connections(limit=200):
    with engine.begin() as conn:
        rows = conn.execute(text("""
            WITH latest AS (
                SELECT hostname, MAX(collected_at) AS captured
                FROM network_connections
                GROUP BY hostname
            )
            SELECT item.*
            FROM network_connections item
            JOIN latest
              ON latest.hostname = item.hostname
             AND latest.captured = item.collected_at
            ORDER BY item.hostname, item.id DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]


def get_network_alerts(limit=100):
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, hostname, alert_type, severity,
                   risk_score, local_address, local_port,
                   title, details, status, created_at
            FROM network_security_alerts
            ORDER BY created_at DESC
            LIMIT :limit
        """), {"limit": limit}).mappings().all()

    return [dict(row) for row in rows]
