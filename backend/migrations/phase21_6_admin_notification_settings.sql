-- ============================================================
-- PHASE 21.6 - ADMIN NOTIFICATION SETTINGS
-- ============================================================

-- 1. Persistent notification settings
CREATE TABLE IF NOT EXISTS notification_settings (

    severity VARCHAR(20) PRIMARY KEY,

    email_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    telegram_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    dashboard_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    updated_by_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,

    created_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_notification_settings_severity
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_critical_dashboard_enabled
        CHECK (
            severity <> 'CRITICAL'
            OR dashboard_enabled = TRUE
        )
);


-- 2. Notification settings audit history
CREATE TABLE IF NOT EXISTS notification_settings_audit (

    id BIGSERIAL PRIMARY KEY,

    severity VARCHAR(20) NOT NULL,

    channel VARCHAR(20) NOT NULL,

    old_enabled BOOLEAN NOT NULL,

    new_enabled BOOLEAN NOT NULL,

    changed_by_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,

    changed_by_username VARCHAR(100) NOT NULL,

    changed_at TIMESTAMP WITHOUT TIME ZONE
        NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_notification_audit_severity
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    CONSTRAINT chk_notification_audit_channel
        CHECK (
            channel IN (
                'EMAIL',
                'TELEGRAM',
                'DASHBOARD'
            )
        ),

    CONSTRAINT chk_notification_audit_change
        CHECK (old_enabled <> new_enabled)
);


-- 3. Indexes
CREATE INDEX IF NOT EXISTS
    ix_notification_settings_audit_changed_at
ON notification_settings_audit (
    changed_at DESC
);

CREATE INDEX IF NOT EXISTS
    ix_notification_settings_audit_severity
ON notification_settings_audit (
    severity,
    changed_at DESC
);


-- 4. Preserve existing notification policies
INSERT INTO notification_settings (
    severity,
    email_enabled,
    telegram_enabled,
    dashboard_enabled
)
VALUES
    ('LOW', FALSE, FALSE, TRUE),
    ('MEDIUM', FALSE, FALSE, TRUE),
    ('HIGH', TRUE, FALSE, TRUE),
    ('CRITICAL', TRUE, TRUE, TRUE)

ON CONFLICT (severity) DO NOTHING;


-- 5. Application database permissions
GRANT SELECT, INSERT, UPDATE
ON notification_settings
TO cyberuser;

GRANT SELECT, INSERT
ON notification_settings_audit
TO cyberuser;

GRANT USAGE, SELECT
ON SEQUENCE notification_settings_audit_id_seq
TO cyberuser;
