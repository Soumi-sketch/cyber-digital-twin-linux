from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models.security_incident_status import (
    SecurityIncidentStatus
)


VALID_STATUSES = [
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED"
]

ALLOWED_TRANSITIONS = {
    "OPEN": ["INVESTIGATING"],
    "INVESTIGATING": ["CONTAINED"],
    "CONTAINED": ["RESOLVED"],
    "RESOLVED": ["CLOSED"],
    "CLOSED": []
}

def get_incident_status(incident_id):

    db: Session = SessionLocal()

    try:

        incident = (
            db.query(SecurityIncidentStatus)
            .filter(
                SecurityIncidentStatus.incident_id
                == incident_id
            )
            .order_by(
                SecurityIncidentStatus.updated_at.desc()
            )
            .first()
        )

        if incident:

            return {
                "incident_id": incident.incident_id,
                "status": incident.status,
                "previous_status": incident.previous_status,
                "notes": incident.notes,
                "updated_at": incident.updated_at
            }

        return None

    finally:

        db.close()

def get_incident_history(incident_id):

    db: Session = SessionLocal()

    try:

        incidents = (
            db.query(SecurityIncidentStatus)
            .filter(
                SecurityIncidentStatus.incident_id
                == incident_id
            )
            .order_by(
                SecurityIncidentStatus.updated_at.asc()
            )
            .all()
        )

        return [
            {
                "id": incident.id,
                "incident_id": incident.incident_id,
                "status": incident.status,
                "previous_status": incident.previous_status,
                "notes": incident.notes,
                "updated_at": incident.updated_at
            }
            for incident in incidents
        ]

    finally:

        db.close()

def ensure_incident_open(incident_id):

    existing = get_incident_status(
        incident_id
    )

    if existing:

        return existing

    return update_incident_status(
        incident_id=incident_id,
        new_status="OPEN",
        notes="Incident automatically registered by detection engine"
    )


def update_incident_status(
    incident_id,
    new_status,
    notes=None
):

    new_status = new_status.upper()

    if new_status not in VALID_STATUSES:

        raise ValueError(
            f"Invalid status. "
            f"Allowed statuses: {VALID_STATUSES}"
        )

    db: Session = SessionLocal()

    try:

        latest_incident = (
            db.query(SecurityIncidentStatus)
            .filter(
                SecurityIncidentStatus.incident_id
                == incident_id
            )
            .order_by(
                SecurityIncidentStatus.updated_at.desc()
            )
            .first()
        )

        previous_status = (
            latest_incident.status
            if latest_incident
            else None
        )

        if previous_status is not None:

            allowed_next_statuses = ALLOWED_TRANSITIONS.get(
                previous_status,
                []
            )

            if new_status not in allowed_next_statuses:

                raise ValueError(
                    f"Invalid lifecycle transition: "
                    f"{previous_status} -> {new_status}. "
                    f"Allowed transitions: "
                    f"{allowed_next_statuses}"
                )

        incident = SecurityIncidentStatus(
            incident_id=incident_id,
            status=new_status,
            previous_status=previous_status,
            notes=notes
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)

        return {
            "id": incident.id,
            "incident_id": incident.incident_id,
            "status": incident.status,
            "previous_status": incident.previous_status,
            "notes": incident.notes,
            "updated_at": incident.updated_at
        }

    except Exception:

        db.rollback()
        raise

    finally:

        db.close()
