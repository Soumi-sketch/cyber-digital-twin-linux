import ipaddress

from sqlalchemy import text
from backend.database import engine


def check_ip_reputation(ip_address: str) -> dict:
    """
    Check an IPv4 or IPv6 address against the local IOC database.
    No network connection is made to the submitted IP.
    """

    try:
        normalized_ip = str(ipaddress.ip_address(ip_address.strip()))
    except (ValueError, AttributeError):
        return {
            "ip_address": ip_address,
            "status": "INVALID",
            "is_malicious": False,
            "message": "Invalid IP address format"
        }

    with engine.connect() as connection:

        record = connection.execute(
            text("""
                SELECT
                    id,
                    indicator_value,
                    threat_type,
                    severity,
                    confidence,
                    source,
                    description,
                    first_seen,
                    last_seen,
                    expires_at
                FROM threat_indicators
                WHERE indicator_type = 'IP'
                  AND indicator_value = :ip
                  AND is_active = TRUE
                  AND (
                      expires_at IS NULL
                      OR expires_at > CURRENT_TIMESTAMP
                  )
                ORDER BY confidence DESC, created_at DESC
                LIMIT 1
            """),
            {"ip": normalized_ip}
        ).mappings().first()

        if record:
            return {
                "ip_address": normalized_ip,
                "status": "MALICIOUS",
                "is_malicious": True,
                "threat": dict(record)
            }

        inactive_record = connection.execute(
            text("""
                SELECT id, indicator_value, source, expires_at
                FROM threat_indicators
                WHERE indicator_type = 'IP'
                  AND indicator_value = :ip
                ORDER BY updated_at DESC
                LIMIT 1
            """),
            {"ip": normalized_ip}
        ).mappings().first()

    if inactive_record:
        return {
            "ip_address": normalized_ip,
            "status": "INACTIVE_OR_EXPIRED",
            "is_malicious": False,
            "message": "A matching IOC exists but is inactive or expired",
            "previous_record": dict(inactive_record)
        }

    return {
        "ip_address": normalized_ip,
        "status": "UNKNOWN",
        "is_malicious": False,
        "message": "No matching IP indicator found"
    }
