from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    TIMESTAMP,
    text
)

from backend.models.system_metrics import Base


class SecurityResponseAudit(Base):

    __tablename__ = "security_response_audit"

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

    incident_type = Column(
        String(100)
    )

    severity = Column(
        String(20)
    )

    source_ip = Column(
        String(50),
        index=True
    )

    threat_score = Column(
        Float
    )

    priority = Column(
        String(20)
    )

    ai_decision = Column(
        String(100)
    )

    recommended_action = Column(
        String(100)
    )

    confidence_score = Column(
        Float
    )

    confidence_level = Column(
        String(20)
    )

    execution_mode = Column(
        String(50)
    )

    executed = Column(
        Boolean,
        default=False
    )

    execution_action = Column(
        String(100)
    )

    execution_message = Column(
        String(500)
    )

    created_at = Column(
        TIMESTAMP,
        server_default=text("CURRENT_TIMESTAMP")
    )
