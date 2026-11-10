
import ipaddress
import requests

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.database import engine


MAX_FEED_SIZE = 2 * 1024 * 1024
FEED_TIMEOUT = (5, 15)
IOC_EXPIRY_HOURS = 24


FEED_SOURCES = {
    "FEODO_TRACKER": {
        "url": (
            "https://feodotracker.abuse.ch/"
            "downloads/ipblocklist_recommended.txt"
        ),
        "indicator_type": "IP",
        "threat_type": "BOTNET_C2",
        "severity": "HIGH",
        "confidence": 90,
    }
}


def fetch_feed(source_name: str) -> dict:
    source = FEED_SOURCES.get(source_name)

    if source is None:
        return {
            "success": False,
            "error": "Feed source is not allowlisted"
        }

    try:
        chunks = []
        total_size = 0

        with requests.get(
            source["url"],
            timeout=FEED_TIMEOUT,
            stream=True,
            headers={
                "User-Agent": "CyberDigitalTwin-ThreatIntel/1.0"
            }
        ) as response:

            response.raise_for_status()

            content_length = response.headers.get("Content-Length")

            if content_length:
                try:
                    if int(content_length) > MAX_FEED_SIZE:
                        return {
                            "success": False,
                            "error": "Feed exceeds the 2 MB size limit"
                        }
                except ValueError:
                    pass

            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue

                total_size += len(chunk)

                if total_size > MAX_FEED_SIZE:
                    return {
                        "success": False,
                        "error": "Feed exceeds the 2 MB size limit"
                    }

                chunks.append(chunk)

        feed_text = b"".join(chunks).decode("utf-8-sig")

        valid_indicators = []
        invalid_count = 0

        for line in feed_text.splitlines():
            value = line.strip()

            if not value or value.startswith("#"):
                continue

            try:
                parsed_ip = ipaddress.ip_address(value)

                if not parsed_ip.is_global:
                    invalid_count += 1
                    continue

                valid_indicators.append(str(parsed_ip))

            except ValueError:
                invalid_count += 1

        indicators = list(dict.fromkeys(valid_indicators))

        if not indicators:
            return {
                "success": False,
                "error": "Feed contains no valid public IP indicators"
            }

        return {
            "success": True,
            "source": source_name,
            "indicator_type": source["indicator_type"],
            "threat_type": source["threat_type"],
            "severity": source["severity"],
            "confidence": source["confidence"],
            "total_valid": len(indicators),
            "invalid_count": invalid_count,
            "preview": indicators[:10],
            "indicators": indicators
        }

    except (requests.RequestException, UnicodeDecodeError) as error:
        return {
            "success": False,
            "error": str(error)
        }


def preview_feed_update(source_name: str) -> dict:
    return fetch_feed(source_name)


def import_feed(source_name: str, dry_run: bool = True) -> dict:
    feed = fetch_feed(source_name)

    if not feed["success"]:
        return feed

    indicators = feed["indicators"]

    new_count = 0
    updated_count = 0

    try:
        with engine.begin() as connection:
            for indicator in indicators:
                existing = connection.execute(
                    text("""
                        SELECT id
                        FROM threat_indicators
                        WHERE indicator_type = :indicator_type
                          AND indicator_value = :indicator_value
                          AND source = :source
                    """),
                    {
                        "indicator_type": feed["indicator_type"],
                        "indicator_value": indicator,
                        "source": source_name
                    }
                ).first()

                if existing:
                    updated_count += 1
                else:
                    new_count += 1

                if not dry_run:
                    connection.execute(
                        text("""
                            INSERT INTO threat_indicators (
                                indicator_type,
                                indicator_value,
                                threat_type,
                                severity,
                                confidence,
                                source,
                                description,
                                first_seen,
                                last_seen,
                                expires_at,
                                is_active,
                                updated_at
                            )
                            VALUES (
                                :indicator_type,
                                :indicator_value,
                                :threat_type,
                                :severity,
                                :confidence,
                                :source,
                                :description,
                                CURRENT_TIMESTAMP,
                                CURRENT_TIMESTAMP,
                                CURRENT_TIMESTAMP
                                    + (:expiry_hours * INTERVAL '1 hour'),
                                TRUE,
                                CURRENT_TIMESTAMP
                            )
                            ON CONFLICT (
                                indicator_type,
                                indicator_value,
                                source
                            )
                            DO UPDATE SET
                                threat_type = EXCLUDED.threat_type,
                                severity = EXCLUDED.severity,
                                confidence = EXCLUDED.confidence,
                                description = EXCLUDED.description,
                                last_seen = CURRENT_TIMESTAMP,
                                expires_at = CURRENT_TIMESTAMP
                                    + (:expiry_hours * INTERVAL '1 hour'),
                                is_active = TRUE,
                                updated_at = CURRENT_TIMESTAMP
                        """),
                        {
                            "indicator_type": feed["indicator_type"],
                            "indicator_value": indicator,
                            "threat_type": feed["threat_type"],
                            "severity": feed["severity"],
                            "confidence": feed["confidence"],
                            "source": source_name,
                            "description": "Imported from " + source_name,
                            "expiry_hours": IOC_EXPIRY_HOURS
                        }
                    )

    except SQLAlchemyError as error:
        return {
            "success": False,
            "error": "Database import failed: " + str(error),
            "database_modified": False
        }

    return {
        "success": True,
        "source": source_name,
        "dry_run": dry_run,
        "total_processed": len(indicators),
        "new_indicators": new_count,
        "updated_indicators": updated_count,
        "database_modified": not dry_run
    }
