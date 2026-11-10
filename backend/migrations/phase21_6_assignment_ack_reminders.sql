-- ============================================================
-- PHASE 21.6 - ASSIGNMENT AND ACKNOWLEDGEMENT REMINDERS
-- ============================================================

CREATE TABLE IF NOT EXISTS security_incident_reminders (

    id BIGSERIAL PRIMARY KEY,

    incident_id VARCHAR(100) NOT NULL,

    reminder_cycle SMALLINT NOT NULL DEFAULT 1,

    reminder_type VARCHAR(30) NOT NULL,

    reminder_level SMALLINT NOT NULL DEFAULT 1,

    severity VARCHAR(20) NOT NULL,

    recipient_user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    recipient_role VARCHAR(50) NOT NULL,

    reminder_after_minutes INTEGER NOT NULL,

    delivery_status VARCHAR(20) NOT NULL DEFAULT 'CREATED',

    triggered_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    read_at TIMESTAMP WITHOUT TIME ZONE,

    created_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_reminder_type
        CHECK (
            reminder_type IN (
                'UNASSIGNED',
                'ACKNOWLEDGEMENT'
            )
        ),

    CONSTRAINT chk_reminder_severity
        CHECK (
            severity IN ('HIGH', 'CRITICAL')
        ),

    CONSTRAINT chk_reminder_status
        CHECK (
            delivery_status IN (
                'CREATED',
                'READ',
                'SKIPPED'
            )
        ),

    CONSTRAINT chk_reminder_cycle
        CHECK (reminder_cycle >= 1),

    CONSTRAINT chk_reminder_level
        CHECK (reminder_level >= 1),

    CONSTRAINT chk_reminder_minutes
        CHECK (reminder_after_minutes > 0),

    CONSTRAINT uq_incident_reminder
        UNIQUE (
            incident_id,
            reminder_cycle,
            reminder_type,
            reminder_level,
            recipient_user_id
        )
);

CREATE INDEX IF NOT EXISTS
    ix_incident_reminders_recipient
ON security_incident_reminders (
    recipient_user_id,
    created_at DESC
);

CREATE INDEX IF NOT EXISTS
    ix_incident_reminders_incident
ON security_incident_reminders (
    incident_id,
    reminder_cycle
);
