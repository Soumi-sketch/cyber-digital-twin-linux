from datetime import timedelta

from sqlalchemy import text

from backend.ai.incident_confidence import calculate_incident_confidence
from backend.database import engine


# ============================================================
# SSH INCIDENT CORRELATION ENGINE
# ============================================================

INCIDENT_WINDOW_MINUTES = 5


# ============================================================
# DETECT SSH INCIDENTS
# ============================================================

def detect_ssh_incidents():

    incidents = []

    with engine.connect() as connection:

        result = connection.execute(
            text(
                """
                SELECT
                    id,
                    event_type,
                    username,
                    source_ip,
                    event_time
                FROM ssh_events
                WHERE event_type IN (
                    'FAILED_LOGIN',
                    'INVALID_USER'
                )
                ORDER BY source_ip ASC, event_time ASC
                LIMIT 500
                """
            )
        )

        events = result.mappings().all()

    # ========================================================
    # GROUP EVENTS BY SOURCE IP
    # ========================================================

    grouped_events = {}

    for event in events:

        source_ip = event["source_ip"]

        if not source_ip:
            continue

        grouped_events.setdefault(
            source_ip,
            []
        ).append(event)

    # ========================================================
    # CORRELATE ATTACK BURSTS
    # ========================================================

    for source_ip, ip_events in grouped_events.items():

        current_incident = []
        previous_time = None

        for event in ip_events:

            event_time = event["event_time"]

            # ------------------------------------------------
            # START NEW INCIDENT
            # ------------------------------------------------

            if not current_incident:

                current_incident = [event]
                previous_time = event_time

                continue

            # ------------------------------------------------
            # CALCULATE TIME GAP
            # ------------------------------------------------

            time_gap = (
                event_time -
                previous_time
            )

            # ------------------------------------------------
            # SAME ATTACK BURST
            # ------------------------------------------------

            if (
                time_gap <=
                timedelta(
                    minutes=INCIDENT_WINDOW_MINUTES
                )
            ):

                current_incident.append(event)

            else:

                # --------------------------------------------
                # CLOSE PREVIOUS INCIDENT
                # --------------------------------------------

                if len(current_incident) >= 3:

                    incidents.append(
                        build_incident(
                            current_incident,
                            source_ip
                        )
                    )

                # --------------------------------------------
                # START NEW INCIDENT
                # --------------------------------------------

                current_incident = [event]

            previous_time = event_time

        # ====================================================
        # CLOSE FINAL INCIDENT
        # ====================================================

        if len(current_incident) >= 3:

            incidents.append(
                build_incident(
                    current_incident,
                    source_ip
                )
            )

    # ========================================================
    # NEWEST INCIDENTS FIRST
    # ========================================================

    incidents.sort(
        key=lambda incident:
            incident["end_time"],
        reverse=True
    )

    return incidents


# ============================================================
# BUILD INCIDENT
# ============================================================

def build_incident(events, source_ip):

    # ========================================================
    # BASIC COUNTS
    # ========================================================

    failed_count = sum(
        1
        for event in events
        if event["event_type"] == "FAILED_LOGIN"
    )

    invalid_count = sum(
        1
        for event in events
        if event["event_type"] == "INVALID_USER"
    )

    total_attempts = len(events)

    # ========================================================
    # TIME INFORMATION
    # ========================================================

    start_time = events[0]["event_time"]
    end_time = events[-1]["event_time"]

    duration_seconds = max(
        0,
        int(
            (
                end_time - start_time
            ).total_seconds()
        )
    )

    duration_minutes = max(
        duration_seconds / 60,
        1 / 60
    )

    # ========================================================
    # ATTACK RATE
    # ========================================================

    attack_rate = round(
        total_attempts / duration_minutes,
        2
    )

    # ========================================================
    # FAILURE RATE
    # ========================================================

    failure_rate = round(
        (
            failed_count /
            total_attempts
        ) * 100,
        2
    )

    # ========================================================
    # DETERMINE SEVERITY
    # ========================================================

    if total_attempts >= 10:

        severity = "CRITICAL"

    elif total_attempts >= 5:

        severity = "HIGH"

    else:

        severity = "MEDIUM"

    # ========================================================
    # DETERMINE USERNAME
    # ========================================================

    usernames = {
        event["username"]
        for event in events
        if event["username"]
    }

    if len(usernames) == 1:

        username = next(
            iter(usernames)
        )

    elif len(usernames) > 1:

        username = "MULTIPLE"

    else:

        username = "UNKNOWN"

    # ========================================================
    # ATTACK PATTERN
    # ========================================================

    if (
        failed_count >= 3
        and attack_rate >= 2
    ):

        attack_pattern = "SSH_BRUTE_FORCE"

    elif invalid_count >= 3:

        attack_pattern = "INVALID_USER_ENUMERATION"

    else:

        attack_pattern = "SUSPICIOUS_SSH_ACTIVITY"

    # ========================================================
    # INCIDENT ID
    # ========================================================

    incident_id = (
        f"SSH-"
        f"{source_ip.replace('.', '')}-"
        f"{int(start_time.timestamp())}"
    )

    # ========================================================
    # CREATE INCIDENT OBJECT
    # ========================================================

    incident = {

        "incident_id":
            incident_id,

        "incident_type":
            "SSH_BRUTE_FORCE",

        "attack_pattern":
            attack_pattern,

        "severity":
            severity,

        "source_ip":
            source_ip,

        "username":
            username,

        "total_attempts":
            total_attempts,

        "failed_logins":
            failed_count,

        "invalid_users":
            invalid_count,

        "attack_rate":
            attack_rate,

        "failure_rate":
            failure_rate,

        "duration_seconds":
            duration_seconds,

        "start_time":
            start_time,

        "end_time":
            end_time,

        "event_ids":
            [
                event["id"]
                for event in events
            ]
    }

    # ========================================================
    # AI INCIDENT CONFIDENCE
    # ========================================================

    confidence = calculate_incident_confidence(
        incident
    )

    incident["confidence_score"] = (
        confidence["confidence_score"]
    )

    incident["confidence_level"] = (
        confidence["confidence_level"]
    )

    incident["confidence_reasons"] = (
        confidence["reasons"]
    )

    return incident


# ============================================================
# DISPLAY INCIDENTS
# ============================================================

def show_incidents():

    incidents = detect_ssh_incidents()

    print(
        "\n================ SSH INCIDENTS ================\n"
    )

    if not incidents:

        print(
            "No correlated SSH incidents found."
        )

        return

    for incident in incidents:

        print(
            f"\n"
            f"Incident ID       : "
            f"{incident['incident_id']}\n"

            f"Severity          : "
            f"{incident['severity']}\n"

            f"Pattern           : "
            f"{incident['attack_pattern']}\n"

            f"Source IP         : "
            f"{incident['source_ip']}\n"

            f"Username          : "
            f"{incident['username']}\n"

            f"Attempts          : "
            f"{incident['total_attempts']}\n"

            f"Failed Logins     : "
            f"{incident['failed_logins']}\n"

            f"Invalid Users     : "
            f"{incident['invalid_users']}\n"

            f"Attack Rate       : "
            f"{incident['attack_rate']} attempts/min\n"

            f"Failure Rate      : "
            f"{incident['failure_rate']}%\n"

            f"Duration          : "
            f"{incident['duration_seconds']} seconds\n"

            f"Confidence        : "
            f"{incident['confidence_level']} "
            f"({incident['confidence_score']}%)\n"

            f"Confidence Reasons: "
            f"{', '.join(incident['confidence_reasons'])}\n"

            f"Start             : "
            f"{incident['start_time']}\n"

            f"End               : "
            f"{incident['end_time']}\n"
        )

    print(
        "\n================================================\n"
    )


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    show_incidents()
