from datetime import datetime, timezone
import json

from sqlalchemy import text
from backend.database import engine


SCENARIOS = {
    "SSH_BRUTE_FORCE": {
        "name": "SSH Brute-force",
        "description": "Estimate the impact of repeated SSH login attempts.",
        "parameters": ["attempts", "unique_ips"],
    },
    "PRIVILEGE_ESCALATION": {
        "name": "Privilege Escalation",
        "description": "Estimate the impact of a hypothetical privilege escalation.",
        "parameters": ["target_privilege", "exploit_complexity"],
    },
    "FILE_TAMPERING": {
        "name": "File Tampering",
        "description": "Estimate the impact of unauthorized critical-file changes.",
        "parameters": ["critical_file", "integrity_protection"],
    },
    "SUSPICIOUS_PROCESS": {
        "name": "Suspicious Process",
        "description": "Estimate the impact of a suspicious process.",
        "parameters": ["process_risk", "privileged"],
    },
    "NETWORK_EXPOSURE": {
        "name": "Network Exposure",
        "description": "Estimate the impact of exposed network services.",
        "parameters": ["exposed_ports", "internet_exposed"],
    },
    "DATA_EXFILTRATION": {
        "name": "Data Exfiltration",
        "description": "Estimate the impact of hypothetical sensitive-data exposure.",
        "parameters": ["data_volume_mb", "sensitive_data", "encrypted"],
    },
}


def _integer(parameters, key, default, minimum, maximum):
    value = parameters.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def _boolean(parameters, key, default):
    value = parameters.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be true or false")
    return value


def _choice(parameters, key, default, allowed):
    value = str(parameters.get(key, default)).lower()
    if value not in allowed:
        raise ValueError(f"{key} must be one of: {', '.join(allowed)}")
    return value


def _severity(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _build_scenario(scenario_type, supplied):
    if not isinstance(supplied, dict):
        raise ValueError("parameters must be an object")

    p = {}
    effects = []
    controls = []
    assets = []

    if scenario_type == "SSH_BRUTE_FORCE":
        attempts = _integer(supplied, "attempts", 10, 1, 10000)
        ips = _integer(supplied, "unique_ips", 1, 1, 1000)
        p = {"attempts": attempts, "unique_ips": ips}
        score = min(100, 20 + min(attempts, 60) + min(ips * 2, 20))
        effects = [
            "Repeated authentication failures",
            "Potential account lockout and service log noise",
            "Possible unauthorized access if credentials are compromised",
        ]
        controls = [
            "Enforce SSH key authentication",
            "Disable direct root login",
            "Apply rate limiting and account lockout policies",
            "Review authentication logs",
        ]

    elif scenario_type == "PRIVILEGE_ESCALATION":
        privilege = _choice(
            supplied, "target_privilege", "root",
            ("user", "sudo", "root")
        )
        complexity = _choice(
            supplied, "exploit_complexity", "medium",
            ("low", "medium", "high")
        )
        p = {
            "target_privilege": privilege,
            "exploit_complexity": complexity,
        }
        score = 30 + {"user": 5, "sudo": 20, "root": 35}[privilege]
        score += {"low": 20, "medium": 10, "high": 0}[complexity]
        effects = [
            f"Hypothetical access escalation to {privilege}",
            "Potential access to protected system resources",
            "Possible compromise of system confidentiality and integrity",
        ]
        controls = [
            "Apply least-privilege permissions",
            "Audit sudoers and privileged groups",
            "Patch vulnerable packages",
            "Monitor privileged command execution",
        ]

    elif scenario_type == "FILE_TAMPERING":
        critical = _boolean(supplied, "critical_file", True)
        protection = _boolean(supplied, "integrity_protection", True)
        p = {
            "critical_file": critical,
            "integrity_protection": protection,
        }
        score = 20 + (35 if critical else 10) + (0 if protection else 30)
        effects = [
            "Possible unauthorized file modification",
            "Potential configuration or application integrity loss",
            "Possible service disruption if critical files are affected",
        ]
        controls = [
            "Enable File Integrity Monitoring",
            "Protect critical files with strict permissions",
            "Maintain verified backups",
            "Investigate unexpected file changes",
        ]

    elif scenario_type == "SUSPICIOUS_PROCESS":
        process_risk = _choice(
            supplied, "process_risk", "high",
            ("low", "medium", "high", "critical")
        )
        privileged = _boolean(supplied, "privileged", False)
        p = {"process_risk": process_risk, "privileged": privileged}
        score = {
            "low": 20, "medium": 40, "high": 65, "critical": 80
        }[process_risk] + (15 if privileged else 0)
        effects = [
            "Potential unauthorized process execution",
            "Possible resource consumption or persistence",
            "Potential abuse of elevated privileges" if privileged
            else "Privilege escalation is not assumed",
        ]
        controls = [
            "Inspect process owner, command line and parent process",
            "Review executable hash and provenance",
            "Apply least privilege",
            "Monitor process creation and service changes",
        ]

    elif scenario_type == "NETWORK_EXPOSURE":
        ports = _integer(supplied, "exposed_ports", 1, 1, 100)
        internet = _boolean(supplied, "internet_exposed", False)
        p = {"exposed_ports": ports, "internet_exposed": internet}
        score = min(100, 20 + ports * 4 + (30 if internet else 0))
        effects = [
            f"{ports} hypothetical exposed service port(s)",
            "Increased attack surface",
            "Greater remote-access risk" if internet
            else "Exposure limited to the modeled internal network",
        ]
        controls = [
            "Review listening services",
            "Restrict access using firewalld",
            "Close unnecessary ports",
            "Use network segmentation",
        ]

    elif scenario_type == "DATA_EXFILTRATION":
        volume = _integer(supplied, "data_volume_mb", 100, 1, 1000000)
        sensitive = _boolean(supplied, "sensitive_data", True)
        encrypted = _boolean(supplied, "encrypted", True)
        p = {
            "data_volume_mb": volume,
            "sensitive_data": sensitive,
            "encrypted": encrypted,
        }
        score = min(
            100,
            15 + min(volume // 10, 30)
            + (30 if sensitive else 0)
            + (15 if not encrypted else 0),
        )
        effects = [
            f"Hypothetical exposure of {volume} MB of data",
            "Potential confidentiality impact" if sensitive
            else "Sensitive data exposure is not assumed",
            "Encryption reduces exposure impact" if encrypted
            else "Unencrypted data increases confidentiality risk",
        ]
        controls = [
            "Apply data access controls",
            "Encrypt sensitive data in transit and at rest",
            "Monitor unusual outbound transfers",
            "Review data access and audit logs",
        ]

    else:
        raise ValueError("Unsupported scenario type")

    score = max(0, min(100, int(score)))
    severity = _severity(score)

    if severity in ("HIGH", "CRITICAL"):
        controls.insert(0, "Escalate for security-team review")

    return {
        "scenario_type": scenario_type,
        "scenario_name": SCENARIOS[scenario_type]["name"],
        "parameters": p,
        "risk_score": score,
        "severity": severity,
        "confidence": 85,
        "predicted_impact": {
            "effects": effects,
            "affected_assets": assets,
            "impact_summary": (
                f"{severity} hypothetical impact with a risk score of {score}/100."
            ),
        },
        "recommended_controls": controls,
        "simulation_mode": "DRY-RUN",
        "disclaimer": (
            "This is a hypothetical model. No attack was executed, "
            "no host was modified and no real incident was created."
        ),
    }


def get_scenarios():
    return [
        {"scenario_type": key, **value}
        for key, value in SCENARIOS.items()
    ]


def run_simulation(
    scenario_type,
    target_hostname,
    parameters,
    user_id,
    username,
):
    scenario_type = str(scenario_type).upper()

    if scenario_type not in SCENARIOS:
        raise ValueError("Unsupported scenario type")

    if target_hostname is not None:
        target_hostname = str(target_hostname).strip()
        if not target_hostname or len(target_hostname) > 253:
            raise ValueError("Invalid target hostname")

    result = _build_scenario(scenario_type, parameters)
    result["predicted_impact"]["affected_assets"] = (
        [target_hostname] if target_hostname else ["Fleet-level hypothetical"]
    )
    result["target_hostname"] = target_hostname
    result["generated_at"] = datetime.now(timezone.utc).isoformat()

    with engine.begin() as connection:
        saved = connection.execute(
            text("""
                INSERT INTO attack_simulations (
                    scenario_type,
                    target_hostname,
                    parameters,
                    result,
                    risk_score,
                    severity,
                    simulation_mode,
                    simulated_by_user_id,
                    simulated_by_username
                )
                VALUES (
                    :scenario_type,
                    :target_hostname,
                    CAST(:parameters AS JSONB),
                    CAST(:result AS JSONB),
                    :risk_score,
                    :severity,
                    'DRY-RUN',
                    :user_id,
                    :username
                )
                RETURNING id, created_at
            """),
            {
                "scenario_type": scenario_type,
                "target_hostname": target_hostname,
                "parameters": json.dumps(result["parameters"]),
                "result": json.dumps(result),
                "risk_score": result["risk_score"],
                "severity": result["severity"],
                "user_id": user_id,
                "username": username,
            },
        ).mappings().one()

    result["simulation_id"] = saved["id"]
    result["created_at"] = saved["created_at"].isoformat()
    return result


def get_simulation_history(limit=50):
    limit = max(1, min(int(limit), 200))

    with engine.connect() as connection:
        rows = connection.execute(
            text("""
                SELECT
                    id, scenario_type, target_hostname,
                    risk_score, severity, simulation_mode,
                    simulated_by_username, created_at, result
                FROM attack_simulations
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            {"limit": limit},
        ).mappings().all()

    return [
        {
            **dict(row),
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]


def get_simulation_detail(simulation_id):
    with engine.connect() as connection:
        row = connection.execute(
            text("""
                SELECT *
                FROM attack_simulations
                WHERE id = :simulation_id
            """),
            {"simulation_id": simulation_id},
        ).mappings().first()

    if not row:
        return None

    result = dict(row)
    result["created_at"] = row["created_at"].isoformat()
    return result
