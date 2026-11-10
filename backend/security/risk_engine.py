from datetime import timedelta

from sqlalchemy import text

from backend.database import engine


# ============================================================
# BASE RISK
# ============================================================

def calculate_base_risk(event):

    event_type = event["event_type"]
    username = event["username"]

    score = 0

    if event_type == "SUCCESSFUL_LOGIN":
        score = 0

    elif event_type == "FAILED_LOGIN":
        score = 20

    elif event_type == "INVALID_USER":
        score = 30

    # Root attack bonus
    if username == "root" and event_type != "SUCCESSFUL_LOGIN":
        score += 20

    return score


# ============================================================
# REPEATED ATTACK RISK
# ============================================================

def calculate_repeat_bonus(connection, event):

    if event["event_type"] not in (
        "FAILED_LOGIN",
        "INVALID_USER"
    ):
        return 0

    source_ip = event["source_ip"]

    result = connection.execute(
        text("""
            SELECT COUNT(DISTINCT (message, event_time))
            FROM ssh_events
            WHERE source_ip = :source_ip
              AND event_type IN (
                  'FAILED_LOGIN',
                  'INVALID_USER'
              )
              AND event_time >= :time_window
              AND event_time <= :event_time
        """),
        {
            "source_ip": source_ip,
            "time_window": (
                event["event_time"]
                - timedelta(minutes=5)
            ),
            "event_time": event["event_time"]
        }
    )

    attempts = result.scalar() or 0

    if attempts >= 10:
        return 50

    elif attempts >= 5:
        return 25

    elif attempts >= 3:
        return 10

    return 0


# ============================================================
# SSH BRUTE FORCE DETECTION
# ============================================================

def detect_bruteforce(
    connection,
    source_ip,
    event_time,
    minutes=5
):

    time_window = event_time - timedelta(
        minutes=minutes
    )

    result = connection.execute(
        text("""
            SELECT COUNT(DISTINCT (message, event_time))
            FROM ssh_events
            WHERE source_ip = :source_ip
              AND event_type IN (
                  'FAILED_LOGIN',
                  'INVALID_USER'
              )
              AND event_time BETWEEN
                  :time_window AND :event_time
        """),
        {
            "source_ip": source_ip,
            "time_window": time_window,
            "event_time": event_time
        }
    )

    attempts = result.scalar() or 0

    if attempts >= 10:

        return {
            "attack_detected": True,
            "attack_type": "SSH_BRUTE_FORCE",
            "severity": "CRITICAL",
            "attempts": attempts
        }

    elif attempts >= 5:

        return {
            "attack_detected": True,
            "attack_type": "SSH_BRUTE_FORCE",
            "severity": "HIGH",
            "attempts": attempts
        }

    return {
        "attack_detected": False,
        "attack_type": None,
        "severity": "LOW",
        "attempts": attempts
    }


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 50:
        return "HIGH"

    elif score >= 20:
        return "MEDIUM"

    return "LOW"


# ============================================================
# ANALYZE SSH EVENTS
# ============================================================

def analyze_ssh_events(event_ids=None):

    if event_ids is not None and not event_ids:
        return []

    with engine.connect() as connection:

        if event_ids is None:

            query = text("""
                SELECT
                    id,
                    event_type,
                    username,
                    source_ip,
                    event_time
                FROM ssh_events
                ORDER BY event_time DESC
                LIMIT 100
            """)

            result = connection.execute(query)

        else:

            from sqlalchemy import bindparam

            query = text("""
                SELECT
                    id,
                    event_type,
                    username,
                    source_ip,
                    event_time
                FROM ssh_events
                WHERE id IN :event_ids
                ORDER BY event_time DESC
            """).bindparams(
                bindparam("event_ids", expanding=True)
            )

            result = connection.execute(
                query,
                {"event_ids": list(event_ids)}
            )

        events = result.mappings().all()
        analyzed_events = []

        for event in events:

            base_score = calculate_base_risk(event)

            repeat_bonus = calculate_repeat_bonus(
                connection,
                event
            )

            total_score = base_score + repeat_bonus

            brute_force = detect_bruteforce(
                connection,
                event["source_ip"],
                event["event_time"]
            )

            attack_type = None
            correlation_type = None

            if brute_force["attack_detected"]:

                if event["event_type"] in (
                    "FAILED_LOGIN",
                    "INVALID_USER"
                ):
                    attack_type = brute_force["attack_type"]

                elif event["event_type"] == "SUCCESSFUL_LOGIN":
                    correlation_type = "SSH_BRUTE_FORCE_SUCCESS"
            risk_level = get_risk_level(total_score)

            if brute_force["severity"] == "CRITICAL":
                risk_level = "CRITICAL"

            elif (
                brute_force["severity"] == "HIGH"
                and risk_level in ("LOW", "MEDIUM")
            ):
                risk_level = "HIGH"

            analyzed_events.append({

                "id": event["id"],
                "event_type": event["event_type"],
                "username": event["username"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "base_score": base_score,
                "repeat_bonus": repeat_bonus,
                "risk_score": total_score,
                "risk_level": risk_level,
                "attack_type": attack_type,
                "correlation_type": correlation_type,
                "bruteforce_attempts": brute_force["attempts"]

            })

        return analyzed_events

# ============================================================
# DISPLAY SUMMARY
# ============================================================

def show_risk_summary():

    events = analyze_ssh_events()

    print(
        "\n================ SECURITY RISK SUMMARY ================\n"
    )

    if not events:

        print("No SSH events found.")

        return


    for event in events:

        print(
            f"ID={event['id']} | "
            f"{event['event_type']} | "
            f"user={event['username']} | "
            f"IP={event['source_ip']} | "
            f"base={event['base_score']} | "
            f"repeat={event['repeat_bonus']} | "
            f"score={event['risk_score']} | "
            f"risk={event['risk_level']} | "
            f"attack={event['attack_type']} | "
            f"attempts={event['bruteforce_attempts']}"
        )


    print(
        "\n========================================================\n"
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    show_risk_summary()
