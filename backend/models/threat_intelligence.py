from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    TIMESTAMP,
    UniqueConstraint,
    text
)

from backend.models.system_metrics import Base


class ThreatIndicator(Base):

    __tablename__ = "threat_indicators"

    __table_args__ = (
        UniqueConstraint(
            "indicator_type",
            "indicator_value",
            "source",
            name="uq_threat_indicator_source"
        ),
    )

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    indicator_type = Column(
        String(30),
        nullable=False,
        index=True
    )

    indicator_value = Column(
        String(500),
        nullable=False,
        index=True
    )

    threat_type = Column(
        String(100),
        nullable=False,
        default="UNKNOWN"
    )

    severity = Column(
        String(20),
        nullable=False,
        default="MEDIUM"
    )

    confidence = Column(
        Integer,
        nullable=False,
        default=50
    )

    source = Column(
        String(150),
        nullable=False
    )

    description = Column(
        Text
    )

    first_seen = Column(
        TIMESTAMP(timezone=True)
    )

    last_seen = Column(
        TIMESTAMP(timezone=True)
    )

    expires_at = Column(
        TIMESTAMP(timezone=True)
    )

    is_active = Column(
        Boolean,
        nullable=False,
        server_default=text("TRUE")
    )

    created_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )

    updated_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP")
    )
