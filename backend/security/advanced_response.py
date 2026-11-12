import json

from sqlalchemy import text
from backend.database import engine


POLICIES = [
    {
        "policy_id": "CRITICAL_CONTAINMENT_REVIEW",
        "name": "Critical threat containment review",
        "severity": ["CRITICAL"],
        "actions": [
            "PRESERVE_EVIDENCE",
            "REVIEW_SOURCE_IP",
            "PREPARE_CONTAINMENT",
            "NOTIFY_SECURITY_TEAM"
        ]
    },
    {
        "policy_id": "HIGH_THREAT_REVIEW",
        "name": "High threat response",
        "severity": ["HIGH"],
        "actions": [
            "PRESERVE_EVIDENCE",
            "ENHANCED_MONITORING",
            "REVIEW_ACCESS",
            "NOTIFY_SECURITY_TEAM"
        ]
    },
    {
        "policy_id": "MEDIUM_THREAT_REVIEW",
        "name": "Medium threat monitoring",
        "severity": ["MEDIUM"],
        "actions": [
            "COLLECT_EVIDENCE",
            "ENHANCED_MONITORING",
            "REVIEW_SOURCE_IP"
        ]
    },
    {
        "policy_id": "LOW_THREAT_REVIEW",
        "name": "Low threat observation",
        "severity": ["LOW"],
        "actions": [
            "RECORD_ACTIVITY",
            "CONTINUE_MONITORING"
        ]
    }
]

PLAYBOOKS = [
    {
        "playbook_id": "SSH_BRUTE_FORCE",
        "name": "SSH brute-force response",
        "incident_types": ["SSH_BRUTE_FORCE", "BRUTE_FORCE"],
        "actions": [
            "PRESERVE_EVIDENCE",
            "REVIEW_SOURCE_IP",
            "ENHANCED_MONITORING",
            "PREPARE_CONTAINMENT"
        ]
    },
    {
        "playbook_id": "PRIVILEGE_ESCALATION",
        "name": "Privilege escalation response",
        "incident_types": ["PRIVILEGE_ESCALATION", "SUSPICIOUS_ROOT_ACTIVITY"],
        "actions": [
            "PRESERVE_EVIDENCE",
            "REVIEW_ACCESS",
            "REVIEW_PRIVILEGED_ACCOUNTS",
            "NOTIFY_SECURITY_TEAM"
        ]
    },
    {
        "playbook_id": "FILE_TAMPERING",
        "name": "File integrity response",
        "incident_types": ["FILE_TAMPERING", "FILE_INTEGRITY"],
        "actions": [
            "PRESERVE_EVIDENCE",
            "REVIEW_FILE_INTEGRITY",
            "PREPARE_RECOVERY"
        ]
    },
    {
        "playbook_id": "SUSPICIOUS_PROCESS",
        "name": "Suspicious process response",
        "incident_types": ["SUSPICIOUS_PROCESS"],
        "actions": [
            "COLLECT_PROCESS_EVIDENCE",
            "REVIEW_PROCESS",
            "ENHANCED_MONITORING"
        ]
    },
    {
        "playbook_id": "NETWORK_EXPOSURE",
        "name": "Network exposure response",
        "incident_types": ["NETWORK_EXPOSURE", "NETWORK_SECURITY"],
        "actions": [
            "COLLECT_NETWORK_EVIDENCE",
            "REVIEW_LISTENING_SERVICES",
            "PREPARE_CONTAINMENT"
        ]
    },
    {
        "playbook_id": "GENERIC_SECURITY",
        "name": "General security response",
        "incident_types": ["*"],
        "actions": [
            "PRESERVE_EVIDENCE",
            "ENHANCED_MONITORING",
            "NOTIFY_SECURITY_TEAM"
        ]
    }
]


def get_policies():
    return POLICIES


def get_playbooks():
    return PLAYBOOKS


def get_threat_mapping():
    return [
        {
            "incident_type": item,
            "playbook_id": playbook["playbook_id"],
            "actions": playbook["actions"]
        }
        for playbook in PLAYBOOKS
        for item in playbook["incident_types"]
    ]


def _select_policy(severity):
    severity = severity.upper()

    for policy in POLICIES:
        if severity in policy["severity"]:
            return policy

    raise ValueError("Unsupported severity")


def _select_playbook(incident_type):
    incident_type = incident_type.upper()

    for playbook in PLAYBOOKS:
        if incident_type in playbook["incident_types"]:
            return playbook

    return PLAYBOOKS[-1]


def _append_audit(connection, run_id, event_type, details, user):
    connection.execute(
        text("""
            INSERT INTO response_orchestration_audit (
                orchestration_id,
                event_type,
                event_details,
                performed_by_user_id,
                performed_by_username
            )
            VALUES (
                :run_id,
                :event_type,
                CAST(:details AS JSONB),
                :user_id,
                :username
            )
        """),
        {
            "run_id": run_id,
            "event_type": event_type,
            "details": json.dumps(details),
            "user_id": user.get("user_id"),
            "username": user.get("sub")
        }
    )


def create_response_plan(data, user):
    severity = data["severity"].upper()

    policy = _select_policy(severity)
    playbook = _select_playbook(data["incident_type"])

    actions = list(dict.fromkeys(
        policy["actions"] + playbook["actions"]
    ))

    with engine.begin() as connection:
        result = connection.execute(
            text("""
                INSERT INTO response_orchestrations (
                    incident_id,
                    incident_type,
                    severity,
                    source_ip,
                    target_hostname,
                    policy_id,
                    playbook_id,
                    planned_actions,
                    reason,
                    created_by_user_id
                )
                VALUES (
                    :incident_id,
                    :incident_type,
                    :severity,
                    :source_ip,
                    :target_hostname,
                    :policy_id,
                    :playbook_id,
                    CAST(:actions AS JSONB),
                    :reason,
                    :user_id
                )
                RETURNING id
            """),
            {
                "incident_id": data["incident_id"],
                "incident_type": data["incident_type"].upper(),
                "severity": severity,
                "source_ip": data.get("source_ip"),
                "target_hostname": data.get("target_hostname"),
                "policy_id": policy["policy_id"],
                "playbook_id": playbook["playbook_id"],
                "actions": json.dumps(actions),
                "reason": data["reason"],
                "user_id": user.get("user_id")
            }
        )

        run_id = result.scalar_one()

        _append_audit(
            connection,
            run_id,
            "PLAN_CREATED",
            {
                "policy_id": policy["policy_id"],
                "playbook_id": playbook["playbook_id"],
                "actions": actions,
                "mode": "DRY-RUN"
            },
            user
        )

    return get_response_run(run_id)


def approve_response(run_id, user):
    with engine.begin() as connection:
        result = connection.execute(
            text("""
                UPDATE response_orchestrations
                SET status = 'APPROVED',
                    approved_by_user_id = :user_id,
                    approved_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :run_id
                  AND status = 'PENDING_APPROVAL'
                  AND created_by_user_id IS DISTINCT FROM :user_id
                RETURNING id
            """),
            {"run_id": run_id, "user_id": user.get("user_id")}
        )

        if result.first() is None:
            raise ValueError(
                "Plan not found or not awaiting approval"
            )

        _append_audit(
            connection,
            run_id,
            "APPROVED",
            {"mode": "DRY-RUN"},
            user
        )

    return get_response_run(run_id)


def execute_response_plan(run_id, user):
    with engine.begin() as connection:
        result = connection.execute(
            text("""
                UPDATE response_orchestrations
                SET status = 'EXECUTED',
                    executed = FALSE,
                    execution_mode = 'DRY-RUN',
                    executed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :run_id
                  AND status = 'APPROVED'
                  AND execution_mode = 'DRY-RUN'
                  AND executed = FALSE
                RETURNING planned_actions, incident_id
            """),
            {"run_id": run_id}
        )

        row = result.mappings().first()

        if row is None:
            raise ValueError(
                "An approved, unexecuted DRY-RUN plan is required"
            )

        _append_audit(
            connection,
            run_id,
            "DRY_RUN_EXECUTED",
            {
                "incident_id": row["incident_id"],
                "planned_actions": row["planned_actions"],
                "executed": False,
                "message": "No remote commands or infrastructure changes performed"
            },
            user
        )

    return get_response_run(run_id)


def record_rollback(run_id, user, reason):
    with engine.begin() as connection:
        result = connection.execute(
            text("""
                UPDATE response_orchestrations
                SET status = 'ROLLBACK_RECORDED',
                    rollback_status = 'DRY_RUN_RECOVERY_RECORDED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :run_id
                  AND status IN ('APPROVED', 'EXECUTED')
                RETURNING id
            """),
            {"run_id": run_id}
        )

        if result.first() is None:
            raise ValueError(
                "Plan must be approved or executed before rollback recording"
            )

        _append_audit(
            connection,
            run_id,
            "ROLLBACK_SIMULATED",
            {
                "reason": reason,
                "mode": "DRY-RUN",
                "infrastructure_changed": False
            },
            user
        )

    return get_response_run(run_id)


def get_response_run(run_id):
    with engine.connect() as connection:
        row = connection.execute(
            text("""
                SELECT *
                FROM response_orchestrations
                WHERE id = :run_id
            """),
            {"run_id": run_id}
        ).mappings().first()

        return dict(row) if row else None


def get_response_history(limit=50):
    with engine.connect() as connection:
        rows = connection.execute(
            text("""
                SELECT *
                FROM response_orchestrations
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"limit": limit}
        ).mappings().all()

        return [dict(row) for row in rows]


def get_response_audit(run_id=None, limit=100):
    with engine.connect() as connection:
        if run_id is None:
            rows = connection.execute(
                text("""
                    SELECT *
                    FROM response_orchestration_audit
                    ORDER BY created_at DESC
                    LIMIT :limit
                """),
                {"limit": limit}
            ).mappings().all()
        else:
            rows = connection.execute(
                text("""
                    SELECT *
                    FROM response_orchestration_audit
                    WHERE orchestration_id = :run_id
                    ORDER BY created_at ASC
                    LIMIT :limit
                """),
                {"run_id": run_id, "limit": limit}
            ).mappings().all()

        return [dict(row) for row in rows]
