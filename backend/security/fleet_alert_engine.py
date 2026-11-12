from datetime import datetime

from sqlalchemy import text
from backend.database import engine

from backend.security.risk_engine import analyze_ssh_events
from backend.security.process_service_monitor import get_process_service_alerts
from backend.security.network_monitor import (
    ensure_phase26_tables,
    get_network_alerts,
)


def _time_value(value):
    if isinstance(value, datetime):
        return value.timestamp()

    if value:
        try:
            return datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            ).timestamp()
        except (ValueError, TypeError, OverflowError):
            pass

    return 0


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else str(value or "")


def _severity(value):
    severity = str(value or "LOW").upper()
    return severity if severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW"


def calculate_fleet_alerts(limit=200):
    limit = max(1, min(int(limit), 500))
    alerts = []

    # Analyze a larger historical SSH window using the existing risk engine.
    with engine.connect() as connection:
        event_ids = connection.execute(text("""
            SELECT id
            FROM ssh_events
            WHERE event_type IN ('FAILED_LOGIN', 'INVALID_USER')
            ORDER BY event_time DESC
            LIMIT 500
        """)).scalars().all()

        host_rows = connection.execute(text("""
            SELECT id, target_hostname, target_ip
            FROM ssh_events
            WHERE id IN :ids
        """).bindparams(
            __import__("sqlalchemy").bindparam("ids", expanding=True)
        ), {"ids": event_ids}).mappings().all() if event_ids else []

    host_mapping = {
        int(row["id"]): {
            "hostname": row["target_hostname"],
            "ip_address": row["target_ip"],
        }
        for row in host_rows
    }

    ssh_events = analyze_ssh_events(event_ids=event_ids)

    for event in ssh_events:
        score = int(event.get("risk_score") or 0)

        if score < 50:
            continue

        event_id = event["id"]
        host = host_mapping.get(event_id, {})

        alerts.append({
            "alert_id": f"SSH-{event_id}",
            "source": "SSH",
            "hostname": host.get("hostname") or "Unattributed",
            "ip_address": host.get("ip_address") or "",
            "alert_type": event.get("event_type") or "SSH_ACTIVITY",
            "severity": "CRITICAL" if score >= 80 else "HIGH",
            "risk_score": score,
            "title": (
                f"Suspicious {event.get('event_type', 'SSH')} activity"
            ),
            "details": (
                f"Username: {event.get('username') or 'Unknown'}; "
                f"Source IP: {event.get('source_ip') or 'Unknown'}"
            ),
            "created_at": _iso(event.get("event_time")),
            "_sort_time": _time_value(event.get("event_time")),
        })

    # Process/service alerts
    for item in get_process_service_alerts(limit):
        created = item.get("created_at")
        alerts.append({
            "alert_id": f"PROCESS-{item.get('id')}",
            "source": "PROCESS_SERVICE",
            "hostname": item.get("hostname") or "Unknown",
            "ip_address": "",
            "alert_type": item.get("alert_type") or "PROCESS_SERVICE",
            "severity": _severity(item.get("severity")),
            "risk_score": int(item.get("risk_score") or 0),
            "title": item.get("title") or "Process/service alert",
            "details": item.get("details") or "",
            "created_at": _iso(created),
            "_sort_time": _time_value(created),
        })

    # Network alerts
    ensure_phase26_tables()

    for item in get_network_alerts(limit):
        created = item.get("created_at")
        alerts.append({
            "alert_id": f"NETWORK-{item.get('id')}",
            "source": "NETWORK",
            "hostname": item.get("hostname") or "Unknown",
            "ip_address": "",
            "alert_type": item.get("alert_type") or "NETWORK_ACTIVITY",
            "severity": _severity(item.get("severity")),
            "risk_score": int(item.get("risk_score") or 0),
            "title": item.get("title") or "Network security alert",
            "details": (
                f"{item.get('details') or ''} "
                f"Port: {item.get('local_port') or 'N/A'}"
            ).strip(),
            "status": item.get("status") or "OPEN",
            "created_at": _iso(created),
            "_sort_time": _time_value(created),
        })

    alerts.sort(
        key=lambda item: item["_sort_time"],
        reverse=True,
    )
    alerts = alerts[:limit]

    severity_counts = {
        level: sum(item["severity"] == level for item in alerts)
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    }

    source_counts = {
        source: sum(item["source"] == source for item in alerts)
        for source in ("SSH", "PROCESS_SERVICE", "NETWORK")
    }

    host_count = len({
        item["hostname"]
        for item in alerts
        if item["hostname"] not in ("Unattributed", "Unknown")
    })

    for item in alerts:
        item.pop("_sort_time", None)

    return {
        "summary": {
            "total_alerts": len(alerts),
            "critical_alerts": severity_counts["CRITICAL"],
            "high_alerts": severity_counts["HIGH"],
            "medium_alerts": severity_counts["MEDIUM"],
            "low_alerts": severity_counts["LOW"],
            "affected_hosts": host_count,
            "source_counts": source_counts,
            "severity_distribution": severity_counts,
        },
        "alerts": alerts,
        "generated_at": datetime.now().astimezone().isoformat(),
    }
