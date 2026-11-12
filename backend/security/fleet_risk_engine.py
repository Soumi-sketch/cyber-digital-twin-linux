from datetime import timedelta

from sqlalchemy import text

from backend.database import engine
from backend.security.risk_engine import analyze_ssh_events
from backend.security.incident_engine import detect_ssh_incidents
from backend.security.cross_server_correlation import (
    detect_cross_server_campaigns
)


# ============================================================
# PHASE 27.7 - FLEET RISK CONFIGURATION
# ============================================================

RISK_WEIGHTS = {
    "event_risk": 0.50,
    "attack_volume": 0.20,
    "campaign_severity": 0.20,
    "incident_severity": 0.10
}

SEVERITY_SCORES = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100
}


def get_fleet_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 20:
        return "MEDIUM"

    return "LOW"


def severity_score(severity):

    return SEVERITY_SCORES.get(
        str(severity or "").upper(),
        0
    )


# ============================================================
# FLEET-WIDE RISK AGGREGATION
# ============================================================

def calculate_fleet_risk():

    # --------------------------------------------------------
    # 1. LOAD REGISTERED HOSTS AND SSH EVENT COUNTS
    # --------------------------------------------------------

    with engine.connect() as connection:

        database_now = connection.execute(
            text("""
                SELECT NOW() AT TIME ZONE 'Asia/Kolkata'
            """)
        ).scalar()

        rows = connection.execute(text("""
            SELECT
                h.hostname,
                h.ip_address,
                h.enabled,
                h.classification,

                COUNT(e.id) FILTER (
                    WHERE e.event_type IN (
                        'FAILED_LOGIN',
                        'INVALID_USER'
                    )
                    AND e.event_time >=
                        NOW() - INTERVAL '24 hours'
                ) AS attacks_24h,

                COUNT(e.id) FILTER (
                    WHERE e.event_type IN (
                        'FAILED_LOGIN',
                        'INVALID_USER'
                    )
                    AND e.event_time >=
                        NOW() - INTERVAL '7 days'
                ) AS attacks_7d,

                COUNT(e.id) FILTER (
                    WHERE e.event_type IN (
                        'FAILED_LOGIN',
                        'INVALID_USER'
                    )
                ) AS attacks_all_time,

                ARRAY_AGG(e.id) FILTER (
                    WHERE e.event_type IN (
                        'FAILED_LOGIN',
                        'INVALID_USER'
                    )
                    AND e.event_time >=
                        NOW() - INTERVAL '24 hours'
                ) AS recent_event_ids

            FROM monitored_hosts h

            LEFT JOIN ssh_events e
                ON (
                    e.target_hostname = h.hostname
                    OR (
                        e.target_hostname IS NULL
                        AND e.target_ip = h.ip_address
                    )
                )

            GROUP BY
                h.hostname,
                h.ip_address,
                h.enabled,
                h.classification

            ORDER BY h.hostname;
        """)).mappings().all()

    hosts = [dict(row) for row in rows]

    # --------------------------------------------------------
    # 2. ANALYZE RECENT EVENTS USING EXISTING RISK ENGINE
    # --------------------------------------------------------

    event_ids = []

    for host in hosts:
        event_ids.extend(
            host.get("recent_event_ids") or []
        )

    analyzed_events = analyze_ssh_events(
        event_ids=event_ids
    ) if event_ids else []

    event_risk_by_id = {
        event["id"]: event["risk_score"]
        for event in analyzed_events
    }

    # --------------------------------------------------------
    # 3. LOAD RECENT INCIDENTS AND CAMPAIGNS
    # --------------------------------------------------------

    incidents = detect_ssh_incidents()

    campaigns = detect_cross_server_campaigns()

    cutoff_24h = database_now - timedelta(hours=24)

    recent_incidents = [
        incident
        for incident in incidents
        if incident.get("end_time")
        and incident["end_time"] >= cutoff_24h
    ]

    # --------------------------------------------------------
    # 4. CALCULATE RISK FOR EACH HOST
    # --------------------------------------------------------

    host_results = []

    for host in hosts:

        if not host["enabled"]:

            host_results.append({
                "hostname": host["hostname"],
                "ip_address": host["ip_address"],
                "classification": host["classification"],
                "enabled": False,
                "risk_score": None,
                "risk_level": "DISABLED",
                "risk_components": None
            })

            continue

        recent_ids = host.get("recent_event_ids") or []

        # Existing event risk component.
        event_score = max(
            (
                event_risk_by_id.get(event_id, 0)
                for event_id in recent_ids
            ),
            default=0
        )

        # Attack volume component.
        attack_volume_score = min(
            100,
            int(host["attacks_24h"] or 0) * 10
        )

        # Recent incident severity component.
        host_all_incidents = [
            incident
            for incident in incidents
            if incident.get("target_hostname") == host["hostname"]
        ]

        host_incidents = [
            incident
            for incident in host_all_incidents
            if incident.get("end_time")
            and incident["end_time"] >= cutoff_24h
        ]

        incident_score = max(
            (
                severity_score(incident.get("severity"))
                for incident in host_incidents
            ),
            default=0
        )

        # Cross-server campaign severity component.
        host_campaigns = [
            campaign
            for campaign in campaigns
            if host["hostname"] in (
                campaign.get("target_hosts") or []
            )
        ]

        campaign_score = max(
            (
                severity_score(campaign.get("severity"))
                for campaign in host_campaigns
            ),
            default=0
        )

        # Weighted fleet risk score.
        weighted_score = (
            event_score * RISK_WEIGHTS["event_risk"]
            + attack_volume_score * RISK_WEIGHTS["attack_volume"]
            + campaign_score * RISK_WEIGHTS["campaign_severity"]
            + incident_score * RISK_WEIGHTS["incident_severity"]
        )

        risk_score = round(
            min(100, weighted_score),
            2
        )

        host_results.append({

            "hostname": host["hostname"],
            "ip_address": host["ip_address"],
            "classification": host["classification"],
            "enabled": True,

            "risk_score": risk_score,
            "risk_level": get_fleet_risk_level(risk_score),

            "risk_components": {
                "event_risk": event_score,
                "attack_volume": attack_volume_score,
                "campaign_severity": campaign_score,
                "incident_severity": incident_score
            },

            "security_activity": {
                "attacks_24h": int(host["attacks_24h"] or 0),
                "attacks_7d": int(host["attacks_7d"] or 0),
                "attacks_all_time": int(
                    host["attacks_all_time"] or 0
                ),
                "recent_incidents": len(host_incidents),
                "historical_incidents": len(host_all_incidents),
                "active_campaigns": len(host_campaigns)
            }
        })

    # --------------------------------------------------------
    # 5. CALCULATE OVERALL FLEET RISK
    # --------------------------------------------------------

    enabled_hosts = [
        host
        for host in host_results
        if host["enabled"]
    ]

    if enabled_hosts:

        fleet_score = round(
            sum(host["risk_score"] for host in enabled_hosts)
            / len(enabled_hosts),
            2
        )

    else:
        fleet_score = 0

    severity_counts = {
        level: sum(
            host["risk_level"] == level
            for host in enabled_hosts
        )
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    }

    return {

        "generated_at": database_now.isoformat(),

        "fleet": {
            "total_hosts": len(host_results),
            "enabled_hosts": len(enabled_hosts),
            "disabled_hosts": (
                len(host_results) - len(enabled_hosts)
            ),
            "fleet_risk_score": fleet_score,
            "fleet_risk_level": get_fleet_risk_level(
                fleet_score
            ),
            "risk_distribution": severity_counts,
            "recent_incidents": len(recent_incidents),
            "historical_incidents": len(incidents),
            "active_cross_server_campaigns": len(campaigns)
        },

        "scoring": {
            "window_hours": 24,
            "trend_window_days": 7,
            "weights": RISK_WEIGHTS
        },

        "hosts": host_results
    }
