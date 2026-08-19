from backend.security.incident_engine import detect_ssh_incidents
from backend.security.response_engine import generate_response
from backend.security.response_executor import execute_response
from fastapi import FastAPI
from backend.security.risk_engine import analyze_ssh_events
from backend.security.alert_engine import generate_security_alerts
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from backend.database import engine
from backend.ai.anomaly_service import analyze_all_metrics
from backend.ai.security_decision_engine import generate_security_decision

app = FastAPI(
    title="AI Powered Cyber Digital Twin",
    version="1.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "Welcome to AI Powered Cyber Digital Twin"
    }


# ============================================================
# ALL METRICS
# ============================================================

@app.get("/metrics")
def get_metrics():

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT *
            FROM system_metrics
            ORDER BY collected_at DESC;
        """))

        return result.mappings().all()


# ============================================================
# HISTORICAL METRICS
# ============================================================

@app.get("/metrics/history")
def get_metrics_history(limit: int = 50):

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT
                hostname,
                cpu_usage,
                memory_usage,
                disk_usage,
                collected_at
            FROM system_metrics
            ORDER BY collected_at DESC
            LIMIT :limit;
        """), {
            "limit": limit
        })

        rows = result.mappings().all()

    # Return oldest → newest for graph plotting
    rows.reverse()

    return rows
# ============================================================
# AI ANOMALY DETECTION
# ============================================================

@app.get("/anomalies")
def get_anomalies():

    return analyze_all_metrics()


# ============================================================
# HOSTS
# ============================================================

@app.get("/hosts")
def get_hosts():

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT DISTINCT hostname, ip_address
            FROM system_metrics
            ORDER BY hostname;
        """))

        return result.mappings().all()


# ============================================================
# CURRENT HEALTH
# ============================================================

@app.get("/health")
def get_health():

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT
                hostname,
                ip_address,
                operating_system,
                kernel_version,
                cpu_usage,
                memory_usage,
                disk_usage,
                uptime,
                collected_at
            FROM system_metrics
            ORDER BY collected_at DESC
            LIMIT 1;
        """))

        row = result.mappings().first()


    # No data in database
    if row is None:
        return {
            "hostname": "Unknown",
            "ip_address": "Unknown",
            "operating_system": "Unknown",
            "kernel_version": "Unknown",
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 0,
            "uptime": "Unknown",
            "status": "Offline",
            "collected_at": None
        }


    # ========================================================
    # HEALTH STATUS
    # ========================================================

    if (
        row["cpu_usage"] > 90
        or row["memory_usage"] > 90
        or row["disk_usage"] > 90
    ):
        status = "Critical"

    elif (
        row["cpu_usage"] > 70
        or row["memory_usage"] > 70
        or row["disk_usage"] > 70
    ):
        status = "Warning"

    else:
        status = "Healthy"


    return {
        "hostname": row["hostname"],
        "ip_address": row["ip_address"],
        "operating_system": row["operating_system"],
        "kernel_version": row["kernel_version"],
        "cpu_usage": row["cpu_usage"],
        "memory_usage": row["memory_usage"],
        "disk_usage": row["disk_usage"],
        "uptime": row["uptime"],
        "status": status,
        "collected_at": row["collected_at"]
    }
# ============================================================
# SSH SECURITY EVENTS
# ============================================================

@app.get("/ssh/events")
def get_ssh_events(limit: int = 20):

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT
                id,
                event_type,
                username,
                source_ip,
                message,
                event_time
            FROM ssh_events
            ORDER BY event_time DESC
            LIMIT :limit;
        """), {
            "limit": limit
        })

        return result.mappings().all()
# ============================================================
# SECURITY RISK API
# ============================================================

@app.get("/security/risk")
def security_risk():

    return analyze_ssh_events()

# ============================================================
# SECURITY ALERT API
# ============================================================

@app.get("/security/alerts")
def security_alerts():

    return generate_security_alerts()

# ============================================================
# SECURITY INCIDENT API
# ============================================================

@app.get("/security/incidents")
def get_security_incidents():

    incidents = detect_ssh_incidents()

    for incident in incidents:

        response = generate_response(incident)

        incident["recommended_action"] = response["recommended_action"]
        incident["response_description"] = response["description"]
        incident["response_mode"] = response["mode"]

    return incidents

# ============================================================
# AI SECURITY RESPONSE EXECUTION API
# ============================================================

@app.get("/security/responses")
def security_responses():

    incidents = detect_ssh_incidents()

    responses = []

    for incident in incidents:

        # Generate explainable AI security decision
        decision = generate_security_decision(
            incident
        )

        # Safely simulate response execution
        execution = execute_response(
            decision
        )

        responses.append({

            "incident_id": decision.get(
                "incident_id"
            ),

            "incident_type": decision.get(
                "incident_type",
                incident.get("incident_type")
            ),

            "severity": decision.get(
                "severity",
                incident.get("severity")
            ),

            "source_ip": decision.get(
                "source_ip",
                incident.get("source_ip")
            ),

            "threat_score": decision.get(
                "threat_score",
                0
            ),

            "priority": decision.get(
                "priority",
                "P4"
            ),

            "ai_decision": decision.get(
                "decision",
                "UNKNOWN"
            ),

            "recommended_action": decision.get(
                "recommended_action",
                "UNKNOWN"
            ),

            "explanation": decision.get(
                "explanation",
                "-"
            ),

            "confidence_score": decision.get(
                "confidence_score",
                0
            ),

            "confidence_level": decision.get(
                "confidence_level",
                "LOW"
            ),

            "execution_mode": execution.get(
                "mode"
            ),

            "executed": execution.get(
                "executed",
                False
            ),

            "execution_action": execution.get(
                "action",
                "UNKNOWN"
            ),

            "execution_message": execution.get(
                "message",
                "-"
            )

        })

    return responses

# ============================================================
# AI SECURITY DECISION API
# ============================================================

@app.get("/security/decisions")
def security_decisions():

    incidents = detect_ssh_incidents()

    decisions = []

    for incident in incidents:

        decision = generate_security_decision(
            incident
        )

        decisions.append(
            decision
        )

    return decisions
