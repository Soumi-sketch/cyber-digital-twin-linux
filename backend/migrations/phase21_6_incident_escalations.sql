-- ============================================================
-- PHASE 21.6: INCIDENT ESCALATION HISTORY
-- ============================================================

CREATE TABLE IF NOT EXISTS security_incident_escalations (

    id BIGSERIAL PRIMARY KEY,

    incident_id VARCHAR(100) NOT NULL,

    escalation_level SMALLINT NOT NULL
        CHECK (escalation_level IN (1, 2)),

    severity VARCHAR(20) NOT NULL
        CHECK (severity IN ('HIGH', 'CRITICAL')),

    notification_channel VARCHAR(20) NOT NULL
        CHECK (notification_channel IN ('email', 'telegram')),

    delivery_status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (
            delivery_status IN (
                'PENDING',
                'SENT',
                'FAILED',
                'SKIPPED'
            )
        ),

    triggered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    sent_at TIMESTAMP,

    error_message VARCHAR(2000),

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_incident_escalation_channel
        UNIQUE (
            incident_id,
            escalation_level,
            notification_channel
        )
);


-- Search escalation history by incident.
CREATE INDEX IF NOT EXISTS
ix_incident_escalations_incident
ON security_incident_escalations(incident_id);


-- Search pending or failed deliveries.
CREATE INDEX IF NOT EXISTS
ix_incident_escalations_delivery
ON security_incident_escalations(delivery_status);


-- Search escalation records by time.
CREATE INDEX IF NOT EXISTS
ix_incident_escalations_triggered
ON security_incident_escalations(triggered_at);


-- ============================================================
-- SUPPORT REOPENED INCIDENT ESCALATION CYCLES
-- ============================================================

ALTER TABLE security_incident_escalations
ADD COLUMN IF NOT EXISTS escalation_cycle SMALLINT
NOT NULL DEFAULT 1;

ALTER TABLE security_incident_escalations
DROP CONSTRAINT IF EXISTS uq_incident_escalation_channel;

ALTER TABLE security_incident_escalations
ADD CONSTRAINT uq_incident_escalation_channel
UNIQUE (
    incident_id,
    escalation_cycle,
    escalation_level,
    notification_channel
);
