from sqlalchemy import (
    Column,
    Integer,
    String,
    TIMESTAMP,
    text
)

from backend.models.system_metrics import Base


class SecurityIncidentWorkflow(Base):

    __tablename__ = "security_incident_workflow"

    incident_id = Column(
        String(100),
        primary_key=True
    )

    assigned_to_user_id = Column(
        Integer
    )

    acknowledged_by_user_id = Column(
        Integer
    )

    acknowledged_at = Column(
        TIMESTAMP
    )

    resolution_summary = Column(
        String(1000)
    )

    updated_by_user_id = Column(
        Integer
    )

    updated_at = Column(
        TIMESTAMP,
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
