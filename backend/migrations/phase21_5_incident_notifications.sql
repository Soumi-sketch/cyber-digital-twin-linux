-- Phase 21.5: Incident-level notification tracking

CREATE TABLE IF NOT EXISTS incident_notification_log (
    id SERIAL PRIMARY KEY,

    incident_id VARCHAR(100) NOT NULL,
    notification_channel VARCHAR(20) NOT NULL,

    severity VARCHAR(20) NOT NULL,
    threat_score INTEGER NOT NULL,
    priority VARCHAR(5) NOT NULL,
    source_ip VARCHAR(50),

    delivery_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,

    last_attempt_at TIMESTAMP,
    sent_at TIMESTAMP,
    error_message TEXT,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT incident_notification_channel_unique
        UNIQUE (incident_id, notification_channel),

    CONSTRAINT incident_notification_status_check
        CHECK (delivery_status IN ('PENDING', 'SENT', 'FAILED')),

    CONSTRAINT incident_notification_attempt_check
        CHECK (attempt_count >= 0)
);

CREATE INDEX IF NOT EXISTS
    ix_incident_notification_status
ON incident_notification_log (delivery_status);

CREATE INDEX IF NOT EXISTS
    ix_incident_notification_created_at
ON incident_notification_log (created_at);
