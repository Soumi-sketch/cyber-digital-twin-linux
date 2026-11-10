
-- ============================================================
-- PHASE 21.6 FEATURE 8 - NOTIFICATION POLICY SIMULATOR
-- ============================================================

CREATE TABLE IF NOT EXISTS notification_simulation_history (

    id BIGSERIAL PRIMARY KEY,

    severity VARCHAR(20) NOT NULL,

    priority VARCHAR(5) NOT NULL,

    email_allowed BOOLEAN NOT NULL,

    telegram_allowed BOOLEAN NOT NULL,

    dashboard_allowed BOOLEAN NOT NULL,

    policy_snapshot JSONB NOT NULL,

    simulation_mode VARCHAR(20) NOT NULL DEFAULT 'DRY-RUN',

    simulated_by_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,

    simulated_by_username VARCHAR(100) NOT NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_simulation_severity
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_simulation_mode
        CHECK (simulation_mode = 'DRY-RUN')
);


-- Indexes

CREATE INDEX IF NOT EXISTS
    ix_notification_simulation_created_at
ON notification_simulation_history (
    created_at DESC
);

CREATE INDEX IF NOT EXISTS
    ix_notification_simulation_severity
ON notification_simulation_history (
    severity,
    created_at DESC
);


-- Application database permissions

GRANT SELECT, INSERT
ON notification_simulation_history
TO cyberuser;

GRANT USAGE, SELECT
ON SEQUENCE notification_simulation_history_id_seq
TO cyberuser;
