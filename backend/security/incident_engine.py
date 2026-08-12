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
                ORDER BY event_time DESC
                LIMIT 100
            """)
        )

        events = result.mappings().all()


        # ====================================================
        # GROUP EVENTS BY SOURCE IP
        # ====================================================

        processed = set()


        for event in events:

            if event["id"] in processed:
                continue


            source_ip = event["source_ip"]

            start_time = event["event_time"]

            end_time = (
                start_time +
                timedelta(minutes=5)
            )


            # =================================================
            # FIND RELATED ATTACK EVENTS
            # =================================================

            related_result = connection.execute(
                text("""
                    SELECT
                        id,
                        event_type,
                        username,
                        source_ip,
                        event_time
                    FROM ssh_events
                    WHERE source_ip = :source_ip
                      AND event_type IN (
                          'FAILED_LOGIN',
                          'INVALID_USER'
                      )
                      AND event_time BETWEEN
                          :start_time AND :end_time
                    ORDER BY event_time ASC
                """),
                {
                    "source_ip": source_ip,
                    "start_time": start_time,
                    "end_time": end_time
                }
            )

            related_events = (
                related_result
                .mappings()
                .all()
            )


            # =================================================
            # ONLY CREATE INCIDENT FOR MULTIPLE ATTEMPTS
            # =================================================

            if len(related_events) < 3:
                continue


            # Mark events as processed

            for related in related_events:
                processed.add(related["id"])


            # =================================================
            # COUNT ATTACK TYPES
            # =================================================

            failed_count = sum(
                1
                for item in related_events
                if item["event_type"] == "FAILED_LOGIN"
            )

            invalid_count = sum(
                1
                for item in related_events
                if item["event_type"] == "INVALID_USER"
            )


            # =================================================
            # DETERMINE SEVERITY
            # =================================================

            total_attempts = len(related_events)


            if total_attempts >= 10:

                severity = "CRITICAL"

            elif total_attempts >= 5:

                severity = "HIGH"

            else:

                severity = "MEDIUM"


            # =================================================
            # INCIDENT
            # =================================================

            incidents.append({

                "incident_type":
                    "SSH_BRUTE_FORCE",

                "severity":
                    severity,

                "source_ip":
                    source_ip,

                "username":
                    event["username"],

                "total_attempts":
                    total_attempts,

                "failed_logins":
                    failed_count,

                "invalid_users":
                    invalid_count,

                "start_time":
                    related_events[0]["event_time"],

                "end_time":
                    related_events[-1]["event_time"],

                "event_ids":
                    [
                        item["id"]
                        for item in related_events
                    ]
            })


    return incidents


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
