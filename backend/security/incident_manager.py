

from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.database import SessionLocal

from backend.security.incident_engine import detect_ssh_incidents

from backend.models.security_incident_status import (
    SecurityIncidentStatus
)

from backend.models.security_incident_workflow import (
    SecurityIncidentWorkflow
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


def _now(db: Session):
    return db.execute(
        text("SELECT LOCALTIMESTAMP")
    ).scalar_one()

def _validate_detected_incident(incident_id):

    incidents = detect_ssh_incidents(limit=None)

    if not any(
        incident.get("incident_id") == incident_id
        for incident in incidents
    ):
        raise ValueError(
            "Incident does not exist in security detection results"
        )

def _latest_status(db: Session, incident_id):

    return (
        db.query(SecurityIncidentStatus)
        .filter(
            SecurityIncidentStatus.incident_id == incident_id
        )
        .order_by(
            SecurityIncidentStatus.updated_at.desc(),
            SecurityIncidentStatus.id.desc()
        )
        .first()
    )


def _get_or_create_workflow(db: Session, incident_id):

    workflow = (
        db.query(SecurityIncidentWorkflow)
        .filter(
            SecurityIncidentWorkflow.incident_id == incident_id
        )
        .first()
    )

    if workflow is None:

        workflow = SecurityIncidentWorkflow(
            incident_id=incident_id
        )

        db.add(workflow)
        db.flush()

    return workflow


def _ensure_open_in_session(db: Session, incident_id):

    latest = _latest_status(db, incident_id)

    if latest is not None:
        return latest

    incident = SecurityIncidentStatus(
        incident_id=incident_id,
        status="OPEN",
        previous_status=None,
        notes="Incident automatically registered by detection engine",
        action="INCIDENT_REGISTERED"
    )

    db.add(incident)
    db.flush()

    return incident


def _append_history(
    db: Session,
    incident_id,
    status,
    previous_status,
    action,
    notes=None,
    changed_by_user_id=None
):

    incident = SecurityIncidentStatus(
        incident_id=incident_id,
        status=status,
        previous_status=previous_status,
        action=action,
        notes=notes,
        changed_by_user_id=changed_by_user_id
    )

    db.add(incident)
    db.flush()

    return incident


def _validate_active_analyst(db: Session, user_id):

    user = db.execute(
        text("""
            SELECT id, username, role, is_active
            FROM users
            WHERE id = :user_id
        """),
        {"user_id": user_id}
    ).mappings().first()

    if user is None:
        raise ValueError("Assigned user does not exist")

    if not user["is_active"]:
        raise ValueError("Assigned user account is inactive")

    if str(user["role"]).lower() != "analyst":
        raise ValueError("Only active analyst accounts can be assigned")

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"]
    }


def _history_dict(incident):

    return {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "status": incident.status,
        "previous_status": incident.previous_status,
        "action": incident.action,
        "notes": incident.notes,
        "changed_by_user_id": incident.changed_by_user_id,
        "updated_at": incident.updated_at
    }


def get_incident_status(incident_id):

    db: Session = SessionLocal()

    try:

        incident = _latest_status(db, incident_id)

        if incident is None:
            return None

        return _history_dict(incident)

    finally:
        db.close()


def get_incident_history(incident_id):

    db: Session = SessionLocal()

    try:

        incidents = (
            db.query(SecurityIncidentStatus)
            .filter(
                SecurityIncidentStatus.incident_id == incident_id
            )
            .order_by(
                SecurityIncidentStatus.updated_at.asc(),
                SecurityIncidentStatus.id.asc()
            )
            .all()
        )

        return [
            _history_dict(incident)
            for incident in incidents
        ]

    finally:
        db.close()


def get_incident_workflow(incident_id):

    db: Session = SessionLocal()

    try:

        workflow = (
            db.query(SecurityIncidentWorkflow)
            .filter(
                SecurityIncidentWorkflow.incident_id == incident_id
            )
            .first()
        )

        if workflow is None:
            return None

        return {
            "incident_id": workflow.incident_id,
            "assigned_to_user_id": workflow.assigned_to_user_id,
            "acknowledged_by_user_id": workflow.acknowledged_by_user_id,
            "acknowledged_at": workflow.acknowledged_at,
            "resolution_summary": workflow.resolution_summary,
            "updated_by_user_id": workflow.updated_by_user_id,
            "updated_at": workflow.updated_at
        }

    finally:
        db.close()


def ensure_incident_open(incident_id):

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)

        incident = _ensure_open_in_session(
            db,
            incident_id
        )

        db.commit()
        db.refresh(incident)

        return _history_dict(incident)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def update_incident_status(
    incident_id,
    new_status,
    notes=None,
    changed_by_user_id=None
):

    if not isinstance(new_status, str):
        raise ValueError("Status must be a string")

    new_status = new_status.strip().upper()

    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status. Allowed statuses: {VALID_STATUSES}"
        )

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)


        latest = _latest_status(db, incident_id)

        previous_status = (
            latest.status if latest else None
        )

        if previous_status is not None:

            allowed = ALLOWED_TRANSITIONS.get(
                previous_status,
                []
            )

            if new_status not in allowed:
                raise ValueError(
                    f"Invalid lifecycle transition: "
                    f"{previous_status} -> {new_status}. "
                    f"Allowed transitions: {allowed}"
                )

        incident = _append_history(
            db=db,
            incident_id=incident_id,
            status=new_status,
            previous_status=previous_status,
            action="STATUS_CHANGED",
            notes=notes,
            changed_by_user_id=changed_by_user_id
        )

        workflow = _get_or_create_workflow(
            db,
            incident_id
        )

        workflow.updated_by_user_id = changed_by_user_id
        workflow.updated_at = _now(db)

        db.commit()
        db.refresh(incident)

        return _history_dict(incident)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def assign_incident(
    incident_id,
    assigned_to_user_id,
    changed_by_user_id
):

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)

        analyst = _validate_active_analyst(
            db,
            assigned_to_user_id
        )

        latest = _ensure_open_in_session(
            db,
            incident_id
        )

        workflow = _get_or_create_workflow(
            db,
            incident_id
        )

        workflow.assigned_to_user_id = analyst["id"]
        workflow.updated_by_user_id = changed_by_user_id
        workflow.updated_at = _now(db)

        incident = _append_history(
            db= db,
            incident_id=incident_id,
            status=latest.status,
            previous_status=latest.status,
            action="ASSIGNED",
            notes=f"Incident assigned to {analyst['username']}",
            changed_by_user_id=changed_by_user_id
        )

        db.commit()
        db.refresh(incident)

        return {
            "incident_id": incident_id,
            "assigned_to": analyst,
            "history": _history_dict(incident)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def acknowledge_incident(
    incident_id,
    acknowledged_by_user_id
):

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)

        latest = _ensure_open_in_session(
            db,
            incident_id
        )

        workflow = _get_or_create_workflow(
            db,
            incident_id
        )

        if workflow.acknowledged_at is not None:
            raise ValueError("Incident has already been acknowledged")

        workflow.acknowledged_by_user_id = acknowledged_by_user_id
        workflow.acknowledged_at = _now(db)
        workflow.updated_by_user_id = acknowledged_by_user_id
        workflow.updated_at = _now(db)

        incident = _append_history(
            db=db,
            incident_id=incident_id,
            status=latest.status,
            previous_status=latest.status,
            action="ACKNOWLEDGED",
            notes="Incident acknowledged",
            changed_by_user_id=acknowledged_by_user_id
        )

        db.commit()
        db.refresh(incident)

        return {
            "incident_id": incident_id,
            "acknowledged": True,
            "acknowledged_by_user_id": acknowledged_by_user_id,
            "acknowledged_at": workflow.acknowledged_at,
            "history": _history_dict(incident)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def add_investigation_note(
    incident_id,
    note,
    changed_by_user_id
):

    if not isinstance(note, str) or not note.strip():
        raise ValueError("Investigation note cannot be empty")

    note = note.strip()

    if len(note) > 500:
        raise ValueError("Investigation note cannot exceed 500 characters")

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)

        latest = _latest_status(db, incident_id)

        if latest is None:
            raise ValueError("Incident does not exist in lifecycle history")

        if latest.status not in ["INVESTIGATING", "CONTAINED"]:
            raise ValueError(
                "Investigation notes require INVESTIGATING or CONTAINED status"
            )

        workflow = _get_or_create_workflow(
            db,
            incident_id
        )

        workflow.updated_by_user_id = changed_by_user_id
        workflow.updated_at = _now(db)

        incident = _append_history(
            db=db,
            incident_id=incident_id,
            status=latest.status,
            previous_status=latest.status,
            action="NOTE_ADDED",
            notes=note,
            changed_by_user_id=changed_by_user_id
        )

        db.commit()
        db.refresh(incident)

        return _history_dict(incident)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def resolve_incident(
    incident_id,
    resolution_summary,
    changed_by_user_id
):

    if (
        not isinstance(resolution_summary, str)
        or not resolution_summary.strip()
    ):
        raise ValueError("Resolution summary cannot be empty")

    resolution_summary = resolution_summary.strip()

    if len(resolution_summary) > 1000:
        raise ValueError("Resolution summary cannot exceed 1000 characters")

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)

        latest = _latest_status(db, incident_id)

        if latest is None:
            raise ValueError("Incident does not exist in lifecycle history")

        if latest.status != "CONTAINED":
            raise ValueError(
                "Only CONTAINED incidents can be resolved"
            )

        workflow = _get_or_create_workflow(
            db,
            incident_id
        )

        workflow.resolution_summary = resolution_summary
        workflow.updated_by_user_id = changed_by_user_id
        workflow.updated_at = _now(db)

        incident = _append_history(
            db=db,
            incident_id=incident_id,
            status="RESOLVED",
            previous_status="CONTAINED",
            action="RESOLVED",
            notes=resolution_summary[:500],
            changed_by_user_id=changed_by_user_id
        )

        db.commit()
        db.refresh(incident)

        return {
            "incident_id": incident_id,
            "resolution_summary": workflow.resolution_summary,
            "history": _history_dict(incident)
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def reopen_incident(
    incident_id,
    notes,
    changed_by_user_id
):

    if not isinstance(notes, str) or not notes.strip():
        raise ValueError("A reopening reason is required")

    notes = notes.strip()

    if len(notes) > 500:
        raise ValueError("Reopening reason cannot exceed 500 characters")

    db: Session = SessionLocal()

    try:

        _validate_detected_incident(incident_id)

        latest = _latest_status(db, incident_id)

        if latest is None:
            raise ValueError("Incident does not exist in lifecycle history")

        if latest.status not in ["RESOLVED", "CLOSED"]:
            raise ValueError(
                "Only RESOLVED or CLOSED incidents can be reopened"
            )

        workflow = _get_or_create_workflow(
            db,
            incident_id
        )

        workflow.resolution_summary = None
        workflow.acknowledged_by_user_id = None
        workflow.acknowledged_at = None
        workflow.updated_by_user_id = changed_by_user_id
        workflow.updated_at = _now(db)

        incident = _append_history(
            db=db,
            incident_id=incident_id,
            status="OPEN",
            previous_status=latest.status,
            action="REOPENED",
            notes=notes,
            changed_by_user_id=changed_by_user_id
        )

        db.commit()
        db.refresh(incident)

        return _history_dict(incident)

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
