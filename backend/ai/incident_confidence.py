# ============================================================
# AI INCIDENT CONFIDENCE ENGINE
# ============================================================


def calculate_incident_confidence(incident):
    """
    Calculate explainable AI confidence for a correlated SSH incident.

    This is a rule-based scoring model.
    It does not modify the firewall or system.
    """

    score = 0
    reasons = []

    attempts = incident.get("total_attempts", 0)
    failed = incident.get("failed_logins", 0)
    invalid = incident.get("invalid_users", 0)
    username = incident.get("username")

    # ========================================================
    # 1. ATTEMPT VOLUME
    # ========================================================

    if attempts >= 10:

        score += 30
        reasons.append(
            "Very high number of SSH authentication attempts"
        )

    elif attempts >= 5:

        score += 20
        reasons.append(
            "Repeated SSH authentication attempts"
        )

    elif attempts >= 3:

        score += 10
        reasons.append(
            "Multiple SSH authentication attempts"
        )

    # ========================================================
    # 2. FAILURE RATE
    # ========================================================

    if attempts > 0:

        failure_rate = (
            failed / attempts
        ) * 100

    else:

        failure_rate = 0

    if failure_rate >= 90:

        score += 30
        reasons.append(
            "Extremely high authentication failure rate"
        )

    elif failure_rate >= 70:

        score += 20
        reasons.append(
            "High authentication failure rate"
        )

    elif failure_rate >= 50:

        score += 10
        reasons.append(
            "Elevated authentication failure rate"
        )

    # ========================================================
    # 3. INVALID USER ACTIVITY
    # ========================================================

    if invalid >= 3:

        score += 15
        reasons.append(
            "Multiple invalid-user attempts detected"
        )

    elif invalid >= 1:

        score += 8
        reasons.append(
            "Invalid-user activity detected"
        )

    # ========================================================
    # 4. ROOT ACCOUNT TARGETING
    # ========================================================

    if username == "root":

        score += 15
        reasons.append(
            "Root account targeted"
        )

    # ========================================================
    # 5. MULTIPLE USERNAMES
    # ========================================================

    if username == "MULTIPLE":

        score += 10
        reasons.append(
            "Multiple usernames targeted"
        )

    # ========================================================
    # LIMIT SCORE
    # ========================================================

    score = min(score, 100)

    # ========================================================
    # CLASSIFICATION
    # ========================================================

    if score >= 80:

        confidence_level = "VERY_HIGH"

    elif score >= 60:

        confidence_level = "HIGH"

    elif score >= 40:

        confidence_level = "MEDIUM"

    else:

        confidence_level = "LOW"

    # ========================================================
    # RESULT
    # ========================================================

    return {
        "confidence_score": score,
        "confidence_level": confidence_level,
        "failure_rate": round(failure_rate, 2),
        "reasons": reasons
    }
