from datetime import timedelta

from sqlalchemy import text

from backend.database import engine


# ============================================================
# CROSS-SERVER ATTACK CORRELATION CONFIGURATION
# ============================================================

CROSS_SERVER_WINDOW_MINUTES = 30
MINIMUM_FAILED_ATTEMPTS = 3
MINIMUM_TARGET_HOSTS = 2


# ============================================================
# BUILD CROSS-SERVER CAMPAIGNS
# ============================================================


def build_cross_server_campaigns(
    events,
    window_minutes=CROSS_SERVER_WINDOW_MINUTES,
    minimum_attempts=MINIMUM_FAILED_ATTEMPTS,
    minimum_hosts=MINIMUM_TARGET_HOSTS
):
    """
    Identify the same source IP attacking multiple
    monitored Linux servers within a rolling time window.
    """

    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than zero")

    if minimum_attempts < 1 or minimum_hosts < 1:
        raise ValueError("Minimum attempts and hosts must be positive")

    if not events:
        return []

    grouped_events = {}

    for event in events:

        source_ip = event.get("source_ip")
        hostname = event.get("target_hostname")

        if not source_ip or not hostname:
            continue

        if event.get("event_type") not in (
            "FAILED_LOGIN",
            "INVALID_USER"
        ):
            continue

        grouped_events.setdefault(source_ip, []).append(event)

    campaigns = []
    window_delta = timedelta(minutes=window_minutes)

    for source_ip, source_events in grouped_events.items():

        source_events.sort(
            key=lambda event: (event["event_time"], event.get("id", 0))
        )

        left = 0

        for right in range(len(source_events)):

            current_time = source_events[right]["event_time"]

            while (
                left <= right
                and current_time - source_events[left]["event_time"]
                > window_delta
            ):
                left += 1

            current_window = source_events[left:right + 1]

            campaign = build_campaign(
                source_ip,
                current_window,
                minimum_attempts,
                minimum_hosts
            )

            if campaign:
                campaigns.append(campaign)


    # Remove campaigns whose event sets are fully contained
    # in a larger qualifying campaign for the same source IP.
    filtered_campaigns = []

    for campaign in campaigns:

        current_ids = set(campaign["event_ids"])

        contained = False

        for other in campaigns:

            if campaign is other:
                continue

            if campaign["source_ip"] != other["source_ip"]:
                continue

            other_ids = set(other["event_ids"])

            if (
                current_ids < other_ids
                or (
                    current_ids == other_ids
                    and campaign["end_time"] < other["end_time"]
                )
            ):
                contained = True
                break

        if not contained:
            filtered_campaigns.append(campaign)

    campaigns = filtered_campaigns

    campaigns.sort(
        key=lambda campaign: campaign["end_time"],
        reverse=True
    )

    return campaigns


# ============================================================
# BUILD ONE CROSS-SERVER CAMPAIGN
# ============================================================

def build_campaign(
    source_ip,
    events,
    minimum_attempts,
    minimum_hosts
):

    target_hosts = sorted({
        event["target_hostname"]
        for event in events
        if event.get("target_hostname")
    })

    total_attempts = len(events)

    if (
        total_attempts < minimum_attempts
        or len(target_hosts) < minimum_hosts
    ):
        return None

    failed_count = sum(
        event["event_type"] == "FAILED_LOGIN"
        for event in events
    )

    invalid_count = sum(
        event["event_type"] == "INVALID_USER"
        for event in events
    )

    start_time = events[0]["event_time"]
    end_time = events[-1]["event_time"]

    # --------------------------------------------------------
    # CAMPAIGN SEVERITY
    # --------------------------------------------------------

    if total_attempts >= 20 or len(target_hosts) >= 4:
        severity = "CRITICAL"

    elif total_attempts >= 10 or len(target_hosts) >= 3:
        severity = "HIGH"

    else:
        severity = "MEDIUM"

    # --------------------------------------------------------
    # CAMPAIGN IDENTIFIER
    # --------------------------------------------------------

    campaign_id = (
        f"XSC-{source_ip.replace('.', '')}-"
        f"{int(start_time.timestamp())}"
    )

    return {
        "campaign_id": campaign_id,
        "campaign_type": "CROSS_SERVER_SSH_ATTACK",
        "source_ip": source_ip,
        "target_hosts": target_hosts,
        "target_count": len(target_hosts),
        "total_attempts": total_attempts,
        "failed_logins": failed_count,
        "invalid_users": invalid_count,
        "severity": severity,
        "start_time": start_time,
        "end_time": end_time,
        "duration_seconds": max(
            0,
            int((end_time - start_time).total_seconds())
        ),
        "event_ids": [
            event["id"]
            for event in events
        ]
    }


# ============================================================
# QUERY DATABASE AND DETECT CAMPAIGNS
# ============================================================

def detect_cross_server_campaigns(
    window_minutes=CROSS_SERVER_WINDOW_MINUTES
):

    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT
                    id,
                    event_type,
                    username,
                    source_ip,
                    target_hostname,
                    target_ip,
                    event_time
                FROM ssh_events
                WHERE event_type IN (
                    'FAILED_LOGIN',
                    'INVALID_USER'
                )
                  AND source_ip IS NOT NULL
                  AND target_hostname IS NOT NULL
                  AND event_time >=
                      NOW() - (
                          CAST(:window_minutes AS INTEGER)
                          * INTERVAL '1 minute'
                      )
                ORDER BY event_time ASC, id ASC
            """),
            {
                "window_minutes": window_minutes
            }
        )

        events = [
            dict(row)
            for row in result.mappings().all()
        ]

    return build_cross_server_campaigns(
        events,
        window_minutes=window_minutes
    )

