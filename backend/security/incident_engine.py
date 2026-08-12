from datetime import timedelta

from sqlalchemy import text

from backend.database import engine


# ============================================================
# SSH INCIDENT CORRELATION
# ============================================================

def detect_ssh_incidents():

    incidents = []

    with engine.connect() as connection:

        result = connection.execute(
            text("""
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
            """)
        )

        events = result.mappings().all()

        # ====================================================
        # GROUP EVENTS INTO ATTACK BURSTS
        # ====================================================

        grouped_events = {}

        for event in events:

            source_ip = event["source_ip"]

            if source_ip not in grouped_events:
                grouped_events[source_ip] = []

            grouped_events[source_ip].append(event)


        # ====================================================
        # PROCESS EACH SOURCE IP
        # ====================================================

        for source_ip, ip_events in grouped_events.items():

            current_incident = []

            previous_time = None

            for event in ip_events:

                event_time = event["event_time"]


                # =================================================
                # START FIRST INCIDENT
                # =================================================

                if not current_incident:

                    current_incident = [event]

                    previous_time = event_time

                    continue


                # =================================================
                # CHECK TIME GAP
                # =================================================

                time_gap = event_time - previous_time


                # =================================================
                # SAME ATTACK BURST
                #
                # If events are within 5 minutes of each other,
                # keep them in the same incident.
                # =================================================

                if time_gap <= timedelta(minutes=5):

                    current_incident.append(event)

                else:

                    # Finish previous incident
                    if len(current_incident) >= 3:

                        incidents.append(
                            build_incident(
                                current_incident,
                                source_ip
                            )
                        )


                    # Start new incident
                    current_incident = [event]


                previous_time = event_time


            # =================================================
            # PROCESS FINAL INCIDENT
            # =================================================

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
        key=lambda incident: incident["end_time"],
        reverse=True
    )


    return incidents


# ============================================================
# BUILD INCIDENT
# ============================================================

def build_incident(events, source_ip):

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

        username = next(iter(usernames))

    elif len(usernames) > 1:

        username = "MULTIPLE"

    else:

        username = "UNKNOWN"


    # ========================================================
    # CREATE INCIDENT
    # ========================================================

    return {

        "incident_type":
            "SSH_BRUTE_FORCE",

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

        "start_time":
            events[0]["event_time"],

        "end_time":
            events[-1]["event_time"],

        "event_ids":
            [
                event["id"]
                for event in events
            ]
    }


# ============================================================
# DISPLAY INCIDENTS
# ============================================================

def show_incidents():

    incidents = detect_ssh_incidents()

    print(
        "\n================ SSH INCIDENTS ================\n"
    )


    if not incidents:

        print("No correlated SSH incidents found.")

        return


    for incident in incidents:

        print(
            f"🚨 {incident['severity']} | "
            f"{incident['incident_type']} | "
            f"IP={incident['source_ip']} | "
            f"user={incident['username']} | "
            f"attempts={incident['total_attempts']} | "
            f"failed={incident['failed_logins']} | "
            f"invalid={incident['invalid_users']}"
        )


    print(
        "\n================================================\n"
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    show_incidents()
