from sqlalchemy import (
    Column,
    Integer,
    String,
    TIMESTAMP,
    text
)

from backend.models.system_metrics import Base


class SecurityIncidentStatus(Base):

    __tablename__ = "security_incident_status"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    incident_id = Column(
        String(100),
        nullable=False,
        index=True
    )

    status = Column(
        String(30),
        nullable=False,
        default="OPEN"
    )

    previous_status = Column(
        String(30)
    )

    notes = Column(
        String(500)
    )

    updated_at = Column(
        TIMESTAMP,
        server_default=text("CURRENT_TIMESTAMP")
    )
