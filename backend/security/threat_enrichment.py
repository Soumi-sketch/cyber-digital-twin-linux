from backend.security.ip_reputation import check_ip_reputation


def enrich_ssh_event(event):
    """
    Enrich an SSH event with local threat intelligence.
    Does not modify the original event or its risk score.
    """

    source_ip = event.get("source_ip")

    reputation = check_ip_reputation(source_ip or "")

    return {
        "threat_intelligence": {
            "checked": True,
            "source_ip": source_ip,
            "status": reputation["status"],
            "is_malicious": reputation["is_malicious"],
            "threat_type": (
                reputation.get("threat", {}).get("threat_type")
                if reputation.get("threat")
                else None
            ),
            "severity": (
                reputation.get("threat", {}).get("severity")
                if reputation.get("threat")
                else None
            ),
            "confidence": (
                reputation.get("threat", {}).get("confidence")
                if reputation.get("threat")
                else None
            ),
            "source": (
                reputation.get("threat", {}).get("source")
                if reputation.get("threat")
                else None
            ),
            "message": reputation.get("message")
        }
    }
