from backend.models.security_response_audit import SecurityResponseAudit
from backend.security.incident_engine import (
    detect_ssh_incidents,
    correlate_incidents
)

from backend.security.incident_manager import (
    get_incident_status,
    get_incident_history,
    get_incident_workflow,
    update_incident_status,
    assign_incident,
    acknowledge_incident,
    add_investigation_note,
    resolve_incident,
    reopen_incident
)

from backend.security.response_engine import generate_response
from backend.security.response_executor import execute_response
from backend.utils.logging_config import (
    configure_logging,
    get_app_logger,
    get_security_logger
)

import time

import shutil
import psutil

from datetime import datetime, timedelta
from backend.config.hosts import HOSTS

from fastapi import FastAPI, HTTPException, Query

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.security.rate_limiter import limiter
from backend.security.risk_engine import analyze_ssh_events
from backend.security.alert_engine import generate_security_alerts
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends
from sqlalchemy import text

from backend.database import engine
from backend.ai.anomaly_service import analyze_all_metrics

from backend.ai.ml_anomaly_detector import (
    train_anomaly_model,
    predict_anomaly
)

from backend.ai.predictive_failure import (
    predict_failure
)

import pandas as pd

from backend.ai.security_decision_engine import generate_security_decision

from backend.auth.routes import (
    router as auth_router
)

from backend.auth.dependencies import (
    get_current_user,
    require_roles
)

from pydantic import BaseModel, Field

app = FastAPI(
    title="AI Powered Cyber Digital Twin",
    version="1.0"
)

class SecurityResponseExecutionRequest(BaseModel):

    reason: str = Field(
        ...,
        min_length=5,
        max_length=500
    )

class IncidentAssignmentRequest(BaseModel):

    assigned_to_user_id: int = Field(
        ...,
        gt=0
    )


class IncidentNoteRequest(BaseModel):

    note: str = Field(
        ...,
        min_length=1,
        max_length=500
    )


class IncidentResolutionRequest(BaseModel):

    resolution_summary: str = Field(
        ...,
        min_length=5,
        max_length=1000
    )


class IncidentReopenRequest(BaseModel):

    reason: str = Field(
        ...,
        min_length=5,
        max_length=500
    )

# ============================================================
# CENTRALIZED LOGGING
# ============================================================

configure_logging()

logger = get_app_logger()
security_logger = get_security_logger()

logger.info("Cyber Digital Twin API initialized")

@app.middleware("http")
async def log_api_requests(request, call_next):
    start_time = time.perf_counter()

    try:
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start_time) * 1000

        logger.info(
            "HTTP %s %s status=%s duration_ms=%.2f",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms
        )

        return response

    except Exception:
        logger.exception(
            "HTTP request failed method=%s path=%s",
            request.method,
            request.url.path
        )
        raise

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)

app.add_middleware(SlowAPIMiddleware)

app.include_router(
    auth_router
)

# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://192.168.38.146"
    ],
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
def get_metrics(
    current_user = Depends(
        get_current_user
    )
):

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
def get_metrics_history(
    limit: int = 50,
    current_user = Depends(
        get_current_user
    )
):

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
def get_anomalies(
    current_user = Depends(
        get_current_user
    )
):

    return analyze_all_metrics()


# ============================================================
# ML ANOMALY DETECTION
# ============================================================

@app.get("/ml/anomalies")
def get_ml_anomalies(
    hostname: str = "prac-server",
    limit: int = 20,
    training_window: int = 1000,
    current_user = Depends(
        get_current_user
    )
):

    query = """
        SELECT
            hostname,
            cpu_usage,
            memory_usage,
            disk_usage,
            collected_at
        FROM system_metrics
        WHERE hostname = :hostname
          AND cpu_usage IS NOT NULL
          AND memory_usage IS NOT NULL
          AND disk_usage IS NOT NULL
        ORDER BY collected_at ASC
    """

    with engine.connect() as connection:

        data = pd.read_sql(
            text(query),
            connection,
            params={
                "hostname": hostname
            }
        )


    if len(data) < 20:

        return {
            "hostname": hostname,
            "status": "Not enough data",
            "samples": len(data),
            "results": []
        }


    model = train_anomaly_model(
        data,
        training_window=training_window
    )

    latest = data.tail(
        limit
    ).copy()


    result = predict_anomaly(
        model,
        latest
    )


    return {
        "hostname": hostname,
        "samples": len(data),
        "anomalies": int(
            result["is_ml_anomaly"].sum()
        ),
        "results": result.to_dict(
            orient="records"
        )
    }

# ============================================================
# PREDICTIVE SYSTEM FAILURE ANALYSIS
# ============================================================

@app.get("/predictive/failure")
def get_predictive_failure(
    hostname: str = "prac-server",
    limit: int = 500,
    current_user = Depends(
        get_current_user
    )
):

    query = """
        SELECT
            hostname,
            cpu_usage,
            memory_usage,
            disk_usage,
            collected_at
        FROM system_metrics
        WHERE hostname = :hostname
          AND cpu_usage IS NOT NULL
          AND memory_usage IS NOT NULL
          AND disk_usage IS NOT NULL
        ORDER BY collected_at ASC
    """

    with engine.connect() as connection:

        data = pd.read_sql(
            text(query),
            connection,
            params={
                "hostname": hostname
            }
        )


    if data.empty:

        return {
            "hostname": hostname,
            "status": "No Data",
            "risk_score": 0,
            "reasons": []
        }


    recent = data.tail(
        limit
    ).copy()


    result = predict_failure(
        recent
    )


    return {
        "hostname": hostname,
        "samples": len(recent),
        **result
    }

# ============================================================
# HOSTS
# ============================================================

@app.get("/hosts")
def get_hosts(
    current_user = Depends(
        get_current_user
    )
):

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
def get_health(
    current_user = Depends(
        get_current_user
    )
):
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
# INFRASTRUCTURE HEALTH MONITORING
# ============================================================

@app.get("/infrastructure/health")
def infrastructure_health(
    current_user=Depends(get_current_user)
):
    components = {}
    host_status = {}
    score = 0

    # API
    components["api"] = "Healthy"
    score += 20

    # DATABASE
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        components["database"] = "Healthy"
        score += 20

    except Exception:
        components["database"] = "Critical"
        logger.exception("Infrastructure database health check failed")

    # COLLECTOR PROCESS
    import psutil

    collector_running = any(
        "collector_runner" in " ".join(
            process.info.get("cmdline") or []
        )
        for process in psutil.process_iter(["cmdline"])
    )

    components["collector"] = (
        "Healthy" if collector_running else "Critical"
    )

    if collector_running:
        score += 20

    # MONITORED HOSTS
    try:
        with engine.connect() as connection:
            result = connection.execute(text("""
                SELECT hostname, MAX(collected_at) AS last_seen
                FROM system_metrics
                GROUP BY hostname;
            """))

            latest_metrics = {
                row["hostname"]: row["last_seen"]
                for row in result.mappings()
            }

        now = datetime.now()

        for host in HOSTS:
            hostname = host["name"]
            last_seen = latest_metrics.get(hostname)

            if last_seen is None:
                status = "NO_DATA"
            else:
                age = (now - last_seen).total_seconds()

                if age <= 30:
                    status = "Healthy"
                else:
                    status = "STALE"

            host_status[hostname] = {
                "status": status,
                "last_seen": last_seen
            }

        if host_status and all(
            item["status"] == "Healthy"
            for item in host_status.values()
        ):
            score += 20

    except Exception:
        logger.exception("Infrastructure host health check failed")
        host_status = {"error": "Host health check unavailable"}

    # CONTROLLER DISK
    try:
        disk = shutil.disk_usage("/")
        disk_percent = round(
            disk.used / disk.total * 100, 2
        )

        disk_status = (
            "Critical" if disk_percent >= 90
            else "Warning" if disk_percent >= 80
            else "Healthy"
        )

        if disk_status == "Healthy":
            score += 20

        components["controller_disk"] = {
            "status": disk_status,
            "usage_percent": disk_percent,
            "free_gb": round(disk.free / (1024 ** 3), 2)
        }

    except Exception:
        logger.exception("Controller disk health check failed")
        components["controller_disk"] = {
            "status": "Unknown"
        }

    overall_status = (
        "Healthy" if score >= 80
        else "Warning" if score >= 60
        else "Critical"
    )

    logger.info(
        "Infrastructure health checked score=%s status=%s",
        score,
        overall_status
    )

    return {
        "health_score": score,
        "overall_status": overall_status,
        "components": components,
        "hosts": host_status
    }

# ============================================================
# SSH SECURITY EVENTS
# ============================================================

@app.get("/ssh/events")
def get_ssh_events(
    limit: int = 20,
    current_user = Depends(
        get_current_user
    )
):

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
def security_risk(
    current_user = Depends(
        get_current_user
    )
):

    return analyze_ssh_events()

# ============================================================
# SECURITY ALERT API
# ============================================================

@app.get("/security/alerts")
def security_alerts(
    current_user = Depends(
        get_current_user
    )
):

    return generate_security_alerts()

# ============================================================
# SECURITY INCIDENT CAMPAIGN API
# ============================================================

@app.get("/security/campaigns")
def get_security_campaigns(
    current_user = Depends(
        get_current_user
    )
):

    incidents = detect_ssh_incidents()

    campaigns = correlate_incidents(
        incidents
    )

    return campaigns

# ============================================================
# SECURITY INCIDENT API
# ============================================================

@app.get("/security/incidents")
def get_security_incidents(
    current_user = Depends(
        get_current_user
    )
):

    incidents = detect_ssh_incidents()

    for incident in incidents:

        lifecycle = get_incident_status(
            incident["incident_id"]
        )

        if lifecycle:

            incident["lifecycle_status"] = (
                lifecycle["status"]
            )

            incident["lifecycle_updated_at"] = (
                lifecycle["updated_at"]
            )

        else:

            incident["lifecycle_status"] = (
                "NOT_REGISTERED"
            )

            incident["lifecycle_updated_at"] = None

        # AI SECURITY INTELLIGENCE

        ai_decision = generate_security_decision(
            incident
        )

        incident["threat_score"] = (
            ai_decision["threat_score"]
        )

        incident["priority"] = (
            ai_decision["priority"]
        )

        incident["ai_decision"] = (
            ai_decision["decision"]
        )

        incident["decision_explanation"] = (
            ai_decision["explanation"]
        )

        response = generate_response(incident)

        incident["recommended_action"] = (
            response["recommended_action"]
        )

        incident["response_description"] = (
            response["description"]
        )

        incident["response_mode"] = (
            response["mode"]
        )

    return incidents


# ============================================================
# SECURITY INCIDENT LIFECYCLE API
# ============================================================


@app.get("/security/incidents/{incident_id}/status")
def get_security_incident_status(
    incident_id: str,
    current_user=Depends(get_current_user)
):

    status = get_incident_status(incident_id)

    if status is None:
        return {
            "incident_id": incident_id,
            "status": "NOT_FOUND"
        }

    return status


@app.get("/security/incidents/{incident_id}/history")
def get_security_incident_history(
    incident_id: str,
    current_user=Depends(get_current_user)
):

    return get_incident_history(incident_id)


@app.get("/security/incidents/{incident_id}/workflow")
def get_security_incident_workflow(
    incident_id: str,
    current_user=Depends(get_current_user)
):

    workflow = get_incident_workflow(incident_id)

    if workflow is None:
        return {
            "incident_id": incident_id,
            "workflow": "NOT_FOUND"
        }

    return workflow


@app.post("/security/incidents/{incident_id}/status")
def update_security_incident_status(
    incident_id: str,
    status: str,
    notes: str = None,
    current_user=Depends(
        require_roles({"admin", "analyst"})
    )
):

    role = current_user.get("role")
    requested_status = status.strip().upper()

    if requested_status == "RESOLVED":
        raise HTTPException(
            status_code=400,
            detail="Use the /resolve endpoint with a resolution summary"
        )

    if role == "analyst" and requested_status not in [
        "INVESTIGATING",
        "CONTAINED"
    ]:
        raise HTTPException(
            status_code=403,
            detail="Analysts cannot perform this status transition"
        )

    if requested_status not in [
        "INVESTIGATING",
        "CONTAINED",
        "CLOSED"
    ]:
        raise HTTPException(
            status_code=400,
            detail="Unsupported status update"
        )

    if requested_status == "CLOSED" and role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Only administrators can close incidents"
        )

    try:

        return update_incident_status(
            incident_id=incident_id,
            new_status=requested_status,
            notes=notes,
            changed_by_user_id=current_user.get("user_id")
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/security/incidents/{incident_id}/assign")
def assign_security_incident(
    incident_id: str,
    request: IncidentAssignmentRequest,
    current_user=Depends(
        require_roles({"admin"})
    )
):

    try:

        return assign_incident(
            incident_id=incident_id,
            assigned_to_user_id=request.assigned_to_user_id,
            changed_by_user_id=current_user.get("user_id")
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/security/incidents/{incident_id}/acknowledge")
def acknowledge_security_incident(
    incident_id: str,
    current_user=Depends(
        require_roles({"admin", "analyst"})
    )
):

    try:

        return acknowledge_incident(
            incident_id=incident_id,
            acknowledged_by_user_id=current_user.get("user_id")
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/security/incidents/{incident_id}/notes")
def add_security_incident_note(
    incident_id: str,
    request: IncidentNoteRequest,
    current_user=Depends(
        require_roles({"admin", "analyst"})
    )
):

    try:

        return add_investigation_note(
            incident_id=incident_id,
            note=request.note,
            changed_by_user_id=current_user.get("user_id")
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/security/incidents/{incident_id}/resolve")
def resolve_security_incident(
    incident_id: str,
    request: IncidentResolutionRequest,
    current_user=Depends(
        require_roles({"admin", "analyst"})
    )
):

    try:

        return resolve_incident(
            incident_id=incident_id,
            resolution_summary=request.resolution_summary,
            changed_by_user_id=current_user.get("user_id")
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/security/incidents/{incident_id}/reopen")
def reopen_security_incident(
    incident_id: str,
    request: IncidentReopenRequest,
    current_user=Depends(
        require_roles({"admin"})
    )
):

    try:

        return reopen_incident(
            incident_id=incident_id,
            notes=request.reason,
            changed_by_user_id=current_user.get("user_id")
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=str(e)
        )


@app.post("/security/incidents/{incident_id}/execute")
def execute_security_incident_response(
    incident_id: str,
    request: SecurityResponseExecutionRequest,
    current_user=Depends(
        require_roles({"admin"})
    )
):

    # Find the incident from server-side detection
    incidents = detect_ssh_incidents()

    incident = next(
        (
            item for item in incidents
            if item["incident_id"] == incident_id
        ),
        None
    )

    if incident is None:

        raise HTTPException(
            status_code=404,
            detail="Security incident not found"
        )

    # Generate the AI decision on the server
    decision = generate_security_decision(
        incident
    )

    # Execute in DRY-RUN mode only
    result = execute_response(
        decision,
        executed_by=current_user.get("sub"),
        executed_by_user_id=current_user.get("user_id"),
        execution_reason=request.reason
    )

    security_logger.info(
        "Admin response processed incident_id=%s username=%s mode=%s audit_saved=%s",
        incident_id,
        current_user.get("sub"),
        result["mode"],
        result["audit_saved"]
    )

    if not result["audit_saved"] and not result["audit_duplicate"]:

        raise HTTPException(
            status_code=500,
            detail="Response audit could not be saved"
        )

    return {
        "incident_id": incident_id,
        **result
    }

# ============================================================
# AI SECURITY RESPONSE EXECUTION API
# ============================================================

@app.get("/security/responses")
def security_responses(
    limit: int = Query(
        default=50,
        ge=1,
        le=200
    ),
    current_user = Depends(
        require_roles(
            {"admin"}
        )
    )
):

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT
                incident_id,
                incident_type,
                severity,
                source_ip,
                threat_score,
                priority,
                ai_decision,
                recommended_action,
                confidence_score,
                confidence_level,
                execution_mode,
                executed,
                execution_action,
                execution_message,
                executed_by,
                executed_by_user_id,
                execution_reason
            FROM security_response_audit
            ORDER BY created_at DESC
            LIMIT :limit;
        """), {
            "limit": limit
        })

        return result.mappings().all()

# ============================================================
# SECURITY RESPONSE AUDIT API
# ============================================================

@app.get("/security/response-audit")
def security_response_audit(
    limit: int = 50,
    current_user = Depends(
        require_roles(
            {
                "admin",
                "analyst",
                "viewer"
            }
        )
    )
):
    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT
                id,
                incident_id,
                incident_type,
                severity,
                source_ip,
                threat_score,
                priority,
                ai_decision,
                recommended_action,
                confidence_score,
                confidence_level,
                execution_mode,
                executed,
                execution_action,
                execution_message,
                executed_by,
                executed_by_user_id,
                execution_reason,
                created_at
            FROM security_response_audit
            ORDER BY created_at DESC
            LIMIT :limit;
        """), {
            "limit": limit
        })

        return result.mappings().all()

# ============================================================
# AI SECURITY DECISION API
# ============================================================

@app.get("/security/decisions")
def security_decisions(
    current_user = Depends(
        get_current_user
    )
):

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
