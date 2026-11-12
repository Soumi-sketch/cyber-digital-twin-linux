CREATE TABLE IF NOT EXISTS response_orchestrations (
    id BIGSERIAL PRIMARY KEY,
    incident_id VARCHAR(100) NOT NULL,
    incident_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip VARCHAR(50),
    target_hostname VARCHAR(253),
    policy_id VARCHAR(60) NOT NULL,
    playbook_id VARCHAR(60) NOT NULL,
    planned_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason VARCHAR(500) NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'PENDING_APPROVAL',
    execution_mode VARCHAR(20) NOT NULL DEFAULT 'DRY-RUN',
    executed BOOLEAN NOT NULL DEFAULT FALSE,
    created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    executed_at TIMESTAMP,
    rollback_status VARCHAR(30) NOT NULL DEFAULT 'NOT_REQUESTED',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT response_orchestration_severity_check
        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    CONSTRAINT response_orchestration_mode_check
        CHECK (execution_mode = 'DRY-RUN'),
    CONSTRAINT response_orchestration_execution_check
        CHECK (executed = FALSE),
    CONSTRAINT response_orchestration_status_check
        CHECK (status IN (
            'PENDING_APPROVAL','APPROVED','EXECUTED',
            'REJECTED','ROLLBACK_RECORDED'
        ))
);

CREATE INDEX IF NOT EXISTS idx_response_orchestration_incident
ON response_orchestrations(incident_id);

CREATE INDEX IF NOT EXISTS idx_response_orchestration_status
ON response_orchestrations(status);

CREATE INDEX IF NOT EXISTS idx_response_orchestration_created
ON response_orchestrations(created_at DESC);

CREATE TABLE IF NOT EXISTS response_orchestration_audit (
    id BIGSERIAL PRIMARY KEY,
    orchestration_id BIGINT NOT NULL
        REFERENCES response_orchestrations(id) ON DELETE RESTRICT,
    event_type VARCHAR(50) NOT NULL,
    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    performed_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    performed_by_username VARCHAR(100),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_response_orchestration_audit_run
ON response_orchestration_audit(orchestration_id);

CREATE INDEX IF NOT EXISTS idx_response_orchestration_audit_created
ON response_orchestration_audit(created_at DESC);
