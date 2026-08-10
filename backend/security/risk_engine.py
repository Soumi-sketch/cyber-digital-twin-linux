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

    source_ip = event["source_ip"]

    result = connection.execute(
        text("""
            SELECT COUNT(*)
            FROM ssh_events
            WHERE source_ip = :source_ip
              AND event_type IN ('FAILED_LOGIN', 'INVALID_USER')
              AND event_time >= :time_window
        """),
        {
            "source_ip": source_ip,
            "time_window": event["event_time"] -
            __import__("datetime").timedelta(minutes=5)
        }
    )

    attempts = result.scalar()

    if attempts >= 10:
        return 50

    elif attempts >= 5:
        return 25

    elif attempts >= 3:
        return 10

    return 0


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

def analyze_ssh_events():

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
                ORDER BY event_time DESC
                LIMIT 100
            """)
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

            analyzed_events.append({
                "id": event["id"],
                "event_type": event["event_type"],
                "username": event["username"],
                "source_ip": event["source_ip"],
                "event_time": event["event_time"],
                "base_score": base_score,
                "repeat_bonus": repeat_bonus,
                "risk_score": total_score,
                "risk_level": get_risk_level(total_score)
            })

    return analyzed_events


# ============================================================
# DISPLAY SUMMARY
# ============================================================

def show_risk_summary():

    events = analyze_ssh_events()

    print("\n================ SECURITY RISK SUMMARY ================\n")

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
            f"risk={event['risk_level']}"
        )

    print("\n========================================================\n")


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    show_risk_summary()
