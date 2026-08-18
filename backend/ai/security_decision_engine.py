from typing import Dict


# ============================================================
# AI SECURITY DECISION ENGINE
# ============================================================
#
# Purpose:
# Convert a correlated security incident into an
# explainable security decision.
#
# Input:
#   Incident data
#   AI confidence
#
# Output:
#   Threat score
#   Priority
#   Decision
#   Explanation
#   Recommended action
#
# IMPORTANT:
# This module ONLY makes a decision.
# It does NOT execute firewall/account changes.
# ============================================================


# ============================================================
# THREAT SCORE
# ============================================================

def calculate_threat_score(incident: Dict) -> int:

    severity = incident.get(
        "severity",
        "LOW"
    )

    confidence = int(
        incident.get(
            "confidence_score",
            0
        )
    )

    attempts = int(
        incident.get(
            "total_attempts",
            0
        )
    )

    failed = int(
        incident.get(
            "failed_logins",
            0
        )
    )

    invalid_users = int(
        incident.get(
            "invalid_users",
            0
        )
    )

    attack_rate = float(
        incident.get(
            "attack_rate",
            0
        )
    )

    # --------------------------------------------------------
    # BASE SCORE FROM INCIDENT SEVERITY
    # --------------------------------------------------------

    severity_scores = {
        "LOW": 10,
        "MEDIUM": 30,
        "HIGH": 50,
        "CRITICAL": 70
    }

    score = severity_scores.get(
        severity.upper(),
        10
    )

    # --------------------------------------------------------
    # AI CONFIDENCE CONTRIBUTION
    # --------------------------------------------------------

    score += round(
        confidence * 0.20
    )

    # --------------------------------------------------------
    # ATTEMPT CONTRIBUTION
    # --------------------------------------------------------

    if attempts >= 10:
        score += 15

    elif attempts >= 5:
        score += 10

    elif attempts >= 3:
        score += 5

    # --------------------------------------------------------
    # FAILURE CONTRIBUTION
    # --------------------------------------------------------

    if failed >= 10:
        score += 10

    elif failed >= 5:
        score += 7

    elif failed >= 3:
        score += 4

    # --------------------------------------------------------
    # INVALID USER CONTRIBUTION
    # --------------------------------------------------------

    if invalid_users >= 3:
        score += 5

    elif invalid_users >= 1:
        score += 2

    # --------------------------------------------------------
    # ATTACK RATE CONTRIBUTION
    # --------------------------------------------------------

    if attack_rate >= 10:
        score += 10

    elif attack_rate >= 5:
        score += 7

    elif attack_rate >= 2:
        score += 4

    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    return min(
        score,
        100
    )


# ============================================================
# PRIORITY
# ============================================================

def determine_priority(
    threat_score: int
) -> str:

    if threat_score >= 80:

        return "P1"

    if threat_score >= 60:

        return "P2"

    if threat_score >= 40:

        return "P3"

    return "P4"


# ============================================================
# SECURITY DECISION
# ============================================================

def determine_decision(
    threat_score: int
) -> str:

    if threat_score >= 90:

        return "IMMEDIATE_CONTAINMENT"

    if threat_score >= 75:

        return "BLOCK_SOURCE_IP"

    if threat_score >= 50:

        return "ENHANCED_MONITORING"

    return "MONITOR"


# ============================================================
# EXPLANATION
# ============================================================

def generate_explanation(
    incident: Dict,
    threat_score: int,
    priority: str,
    decision: str
) -> str:

    reasons = []

    severity = incident.get(
        "severity",
        "LOW"
    )

    confidence = incident.get(
        "confidence_score",
        0
    )

    attempts = incident.get(
        "total_attempts",
        0
    )

    failed = incident.get(
        "failed_logins",
        0
    )

    invalid_users = incident.get(
        "invalid_users",
        0
    )

    attack_rate = incident.get(
        "attack_rate",
        0
    )

    source_ip = incident.get(
        "source_ip",
        "unknown"
    )

    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    if severity in (
        "HIGH",
        "CRITICAL"
    ):

        reasons.append(
            f"{severity} incident severity"
        )

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    if confidence >= 70:

        reasons.append(
            f"high AI confidence ({confidence}%)"
        )

    elif confidence >= 50:

        reasons.append(
            f"moderate AI confidence ({confidence}%)"
        )

    # --------------------------------------------------------
    # ATTEMPTS
    # --------------------------------------------------------

    if attempts >= 10:

        reasons.append(
            f"very high authentication activity ({attempts} attempts)"
        )

    elif attempts >= 5:

        reasons.append(
            f"repeated authentication attempts ({attempts})"
        )

    # --------------------------------------------------------
    # FAILURE RATE
    # --------------------------------------------------------

    if attempts > 0:

        failure_rate = (
            failed /
            attempts
        ) * 100

        if failure_rate >= 80:

            reasons.append(
                f"extremely high failure rate ({failure_rate:.1f}%)"
            )

        elif failure_rate >= 50:

            reasons.append(
                f"high failure rate ({failure_rate:.1f}%)"
            )

    # --------------------------------------------------------
    # INVALID USERS
    # --------------------------------------------------------

    if invalid_users > 0:

        reasons.append(
            f"invalid-user activity detected ({invalid_users})"
        )

    # --------------------------------------------------------
    # ATTACK RATE
    # --------------------------------------------------------

    if attack_rate >= 10:

        reasons.append(
            f"very high attack rate ({attack_rate} attempts/min)"
        )

    elif attack_rate >= 5:

        reasons.append(
            f"elevated attack rate ({attack_rate} attempts/min)"
        )

    # --------------------------------------------------------
    # BUILD EXPLANATION
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "limited evidence of malicious activity"
        )

    explanation = (
        f"Source {source_ip} produced a "
        f"{severity} security incident. "
        f"The AI calculated a threat score of "
        f"{threat_score}/100 with priority "
        f"{priority}. "
        f"Decision: {decision}. "
        f"Evidence: "
        f"{'; '.join(reasons)}."
    )

    return explanation


# ============================================================
# COMPLETE SECURITY DECISION
# ============================================================

def generate_security_decision(
    incident: Dict
) -> Dict:

    threat_score = calculate_threat_score(
        incident
    )

    priority = determine_priority(
        threat_score
    )

    decision = determine_decision(
        threat_score
    )

    explanation = generate_explanation(
        incident,
        threat_score,
        priority,
        decision
    )

    return {

        "incident_id":
            incident.get(
                "incident_id"
            ),

        "source_ip":
            incident.get(
                "source_ip"
            ),

        "incident_type":
            incident.get(
                "incident_type"
            ),

        "severity":
            incident.get(
                "severity"
            ),

        "confidence_score":
            incident.get(
                "confidence_score",
                0
            ),

        "confidence_level":
            incident.get(
                "confidence_level",
                "UNKNOWN"
            ),

        "threat_score":
            threat_score,

        "priority":
            priority,

        "decision":
            decision,

        "recommended_action":
            decision,

        "explanation":
            explanation,

        "execution_mode":
            "DRY-RUN"

    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_incident = {

        "incident_id":
            "SSH-TEST-001",

        "source_ip":
            "192.168.38.146",

        "incident_type":
            "SSH_BRUTE_FORCE",

        "severity":
            "HIGH",

        "confidence_score":
            70,

        "confidence_level":
            "HIGH",

        "total_attempts":
            10,

        "failed_logins":
            10,

        "invalid_users":
            0,

        "attack_rate":
            10.0

    }

    decision = generate_security_decision(
        test_incident
    )

    print(
        "\n=============================="
    )

    print(
        "AI SECURITY DECISION"
    )

    print(
        "=============================="
    )

    for key, value in decision.items():

        print(
            f"{key}: {value}"
        )
