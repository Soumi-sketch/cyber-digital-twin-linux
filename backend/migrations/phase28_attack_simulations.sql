CREATE TABLE IF NOT EXISTS attack_simulations (
    id BIGSERIAL PRIMARY KEY,
    scenario_type VARCHAR(40) NOT NULL,
    target_hostname VARCHAR(253),
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity VARCHAR(20) NOT NULL CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    simulation_mode VARCHAR(20) NOT NULL DEFAULT 'DRY-RUN'
        CHECK (simulation_mode = 'DRY-RUN'),
    simulated_by_user_id INTEGER
        REFERENCES users(id) ON DELETE SET NULL,
    simulated_by_username VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_attack_simulations_created
ON attack_simulations (created_at DESC);

CREATE INDEX IF NOT EXISTS ix_attack_simulations_severity
ON attack_simulations (severity, created_at DESC);

CREATE INDEX IF NOT EXISTS ix_attack_simulations_scenario
ON attack_simulations (scenario_type, created_at DESC);

GRANT SELECT, INSERT ON attack_simulations TO cyberuser;
GRANT USAGE, SELECT ON SEQUENCE attack_simulations_id_seq TO cyberuser;
