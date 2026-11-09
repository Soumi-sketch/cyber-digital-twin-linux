-- Phase 21.4: Incident Acknowledgement and Resolution

-- Extend existing lifecycle history
ALTER TABLE security_incident_status
ADD COLUMN IF NOT EXISTS action VARCHAR(40);

ALTER TABLE security_incident_status
ADD COLUMN IF NOT EXISTS changed_by_user_id INTEGER
REFERENCES users(id) ON DELETE SET NULL;

-- Current incident workflow information
CREATE TABLE IF NOT EXISTS security_incident_workflow (
    incident_id VARCHAR(100) PRIMARY KEY,

    assigned_to_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,

    acknowledged_by_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,

    acknowledged_at TIMESTAMP,

    resolution_summary VARCHAR(1000),

    updated_by_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,

    updated_at TIMESTAMP
        NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for analyst assignment searches
CREATE INDEX IF NOT EXISTS
ix_security_incident_workflow_assigned_to
ON security_incident_workflow(assigned_to_user_id);
