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

from backend.analytics.notification_analytics import (
    get_notification_analytics
)

from backend.ai.anomaly_service import analyze_all_metrics
from backend.notifications.delivery_health_monitor import (
    get_delivery_health
)

from backend.notifications.notification_settings_manager import (
    get_notification_settings,
    update_notification_setting,
    get_notification_settings_audit
)

from backend.notifications.notification_simulator import (
    simulate_notification_policy,
    get_notification_simulation_history
)

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

class NotificationSettingUpdateRequest(BaseModel):

    enabled: bool

class NotificationSimulationRequest(BaseModel):

    severity: str = Field(
        ...,
        min_length=3,
        max_length=20
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
# ADMIN NOTIFICATION SETTINGS API
# ============================================================

@app.get("/security/notification-settings")
def notification_settings_api(
    current_user=Depends(
        require_roles(
            {"admin", "analyst", "viewer"}
        )
    )
):

    try:

        return get_notification_settings()

    except Exception:

        get_app_logger().exception(
            "NOTIFICATION SETTINGS API ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve notification settings"
        )


@app.put("/security/notification-settings/{severity}/{channel}")
def update_notification_settings_api(
    severity: str,
    channel: str,
    request: NotificationSettingUpdateRequest,
    current_user=Depends(
        require_roles({"admin"})
    )
):

    try:

        return update_notification_setting(
            severity=severity,
            channel=channel,
            enabled=request.enabled,
            changed_by_user_id=current_user.get("user_id"),
            changed_by_username=current_user.get("sub")
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except RuntimeError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

    except Exception:

        get_app_logger().exception(
            "NOTIFICATION SETTINGS UPDATE ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to update notification settings"
        )


@app.get("/security/notification-settings/audit")
def notification_settings_audit_api(
    limit: int = Query(
        default=100,
        ge=1,
        le=500
    ),
    current_user=Depends(
        require_roles(
            {"admin", "analyst", "viewer"}
        )
    )
):

    try:

        return get_notification_settings_audit(
            limit=limit
        )

    except Exception:

        get_app_logger().exception(
            "NOTIFICATION SETTINGS AUDIT API ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve notification settings audit"
        )

# ============================================================
# INCIDENT NOTIFICATION HISTORY API
# ============================================================

@app.get("/security/notification-history")
def get_notification_history(
    limit: int = Query(
        default=50,
        ge=1,
        le=200
    ),
    current_user=Depends(
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

        result = connection.execute(
            text("""
                SELECT
                    id,
                    incident_id,
                    notification_channel,
                    severity,
                    threat_score,
                    priority,
                    source_ip,
                    delivery_status,
                    attempt_count,
                    last_attempt_at,
                    sent_at,
                    error_message,
                    created_at,
                    updated_at
                FROM incident_notification_log
                ORDER BY created_at DESC, id DESC
                LIMIT :limit
            """),
            {
                "limit": limit
            }
        )

        records = [
            dict(row)
            for row in result.mappings().all()
        ]

        role = current_user.get("role")

        if role == "viewer":

            for record in records:
                record.pop("error_message", None)

        return records


# ============================================================
# NOTIFICATION DELIVERY HEALTH API
# ============================================================

@app.get("/security/delivery-health")
def get_notification_delivery_health(
    current_user=Depends(
        require_roles(
            {
                "admin",
                "analyst",
                "viewer"
            }
        )
    )
):

    try:

        return get_delivery_health()

    except Exception as error:

        get_app_logger().exception(
            "DELIVERY HEALTH API ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve notification delivery health"
        )

# ============================================================
# NOTIFICATION ANALYTICS API
# ============================================================

@app.get("/security/notification-analytics")
def notification_analytics_api(
    days: int = 90,
    period: str = "daily",
    current_user=Depends(
        require_roles(
            {
                "admin",
                "analyst",
                "viewer"
            }
        )
    )
):

    try:

        return get_notification_analytics(
            days=days,
            period=period
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:

        get_app_logger().exception(
            "NOTIFICATION ANALYTICS API ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve notification analytics"
        )


# ============================================================
# PHASE 21.6 FEATURE 8 - NOTIFICATION POLICY SIMULATOR API
# ============================================================

@app.post("/security/notification-simulator")
def notification_simulator_api(
    request: NotificationSimulationRequest,
    current_user=Depends(
        require_roles(
            {"admin", "analyst", "viewer"}
        )
    )
):

    try:

        return simulate_notification_policy(
            severity=request.severity,
            simulated_by_user_id=current_user.get("user_id"),
            simulated_by_username=current_user.get("sub")
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:

        get_app_logger().exception(
            "NOTIFICATION SIMULATION API ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to simulate notification policy"
        )


@app.get("/security/notification-simulator/history")
def notification_simulation_history_api(
    limit: int = Query(
        default=50,
        ge=1,
        le=200
    ),
    current_user=Depends(
        require_roles(
            {"admin", "analyst", "viewer"}
        )
    )
):

    try:

        return get_notification_simulation_history(
            limit=limit
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:

        get_app_logger().exception(
            "NOTIFICATION SIMULATION HISTORY API ERROR"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve simulation history"
        )


# ============================================================
# INCIDENT ASSIGNMENT AND ACKNOWLEDGEMENT REMINDER API
# ============================================================


@app.get("/security/reminders")
def get_security_reminders(
    limit: int = Query(
        default=50,
        ge=1,
        le=200
    ),
    current_user=Depends(get_current_user)
):

    role = str(
        current_user.get("role", "")
    ).lower()

    user_id = current_user.get("user_id")

    if role == "viewer":
        return []

    if role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions"
        )

    if role == "analyst" and user_id is None:
        raise HTTPException(
            status_code=401,
            detail="User identity missing"
        )

    with engine.connect() as connection:

        if role == "admin":

            result = connection.execute(
                text("""
                    SELECT
                        r.id,
                        r.incident_id,
                        r.reminder_cycle,
                        r.reminder_type,
                        r.severity,
                        r.recipient_user_id,
                        u.username AS recipient_username,
                        r.recipient_role,
                        r.reminder_after_minutes,
                        r.delivery_status,
                        r.triggered_at,
                        r.read_at,
                        r.created_at
                    FROM security_incident_reminders r
                    JOIN users u
                        ON u.id = r.recipient_user_id
                    ORDER BY r.created_at DESC, r.id DESC
                    LIMIT :limit
                """),
                {"limit": limit}
            )

        else:

            result = connection.execute(
                text("""
                    SELECT
                        r.id,
                        r.incident_id,
                        r.reminder_cycle,
                        r.reminder_type,
                        r.severity,
                        r.recipient_user_id,
                        u.username AS recipient_username,
                        r.recipient_role,
                        r.reminder_after_minutes,
                        r.delivery_status,
                        r.triggered_at,
                        r.read_at,
                        r.created_at
                    FROM security_incident_reminders r
                    JOIN users u
                        ON u.id = r.recipient_user_id
                    WHERE r.recipient_user_id = :user_id
                    ORDER BY r.created_at DESC, r.id DESC
                    LIMIT :limit
                """),
                {
                    "user_id": user_id,
                    "limit": limit
                }
            )

        return [
            dict(row)
            for row in result.mappings().all()
        ]


# ============================================================
# MARK INCIDENT REMINDER AS READ
# ============================================================


@app.post("/security/reminders/{reminder_id}/read")
def mark_reminder_as_read(
    reminder_id: int,
    current_user=Depends(get_current_user)
):

    role = str(
        current_user.get("role", "")
    ).lower()

    user_id = current_user.get("user_id")

    if role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions"
        )

    if role == "analyst" and user_id is None:
        raise HTTPException(
            status_code=401,
            detail="User identity missing"
        )

    with engine.begin() as connection:

        if role == "admin":

            result = connection.execute(
                text("""
                    UPDATE security_incident_reminders
                    SET
                        delivery_status = 'READ',
                        read_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :reminder_id
                    AND delivery_status = 'CREATED'
                    RETURNING id, delivery_status, read_at
                """),
                {"reminder_id": reminder_id}
            )

        else:

            result = connection.execute(
                text("""
                    UPDATE security_incident_reminders
                    SET
                        delivery_status = 'READ',
                        read_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = :reminder_id
                    AND recipient_user_id = :user_id
                    AND delivery_status = 'CREATED'
                    RETURNING id, delivery_status, read_at
                """),
                {
                    "reminder_id": reminder_id,
                    "user_id": user_id
                }
            )

        record = result.mappings().first()

        if record is not None:

            return {
                "message": "Reminder marked as read",
                **dict(record)
            }

        # Check whether the reminder exists and is visible.
        if role == "admin":

            existing = connection.execute(
                text("""
                    SELECT id, delivery_status, read_at
                    FROM security_incident_reminders
                    WHERE id = :reminder_id
                """),
                {"reminder_id": reminder_id}
            ).mappings().first()

        else:

            existing = connection.execute(
                text("""
                    SELECT id, delivery_status, read_at
                    FROM security_incident_reminders
                    WHERE id = :reminder_id
                    AND recipient_user_id = :user_id
                """),
                {
                    "reminder_id": reminder_id,
                    "user_id": user_id
                }
            ).mappings().first()

        if existing is None:
            raise HTTPException(
                status_code=404,
                detail="Reminder not found"
            )

        if existing["delivery_status"] == "READ":

            return {
                "message": "Reminder was already read",
                **dict(existing)
            }

        raise HTTPException(
            status_code=409,
            detail="Reminder cannot be marked as read"
        )


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


# ============================================================
# PHASE 22 - THREAT INTELLIGENCE / IOC MANAGEMENT
# ============================================================

from typing import Literal


class ThreatIndicatorCreate(BaseModel):

    indicator_type: Literal[
        "IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"
    ]

    indicator_value: str = Field(
        ...,
        min_length=3,
        max_length=500
    )

    threat_type: str = Field(
        default="UNKNOWN",
        max_length=100
    )

    severity: Literal[
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    ] = "MEDIUM"

    confidence: int = Field(
        default=50,
        ge=0,
        le=100
    )

    source: str = Field(
        ...,
        min_length=2,
        max_length=150
    )

    description: str | None = None


@app.post("/threat-intelligence/indicators")
def create_threat_indicator(
    data: ThreatIndicatorCreate,
    current_user=Depends(require_roles(["admin"]))
):

    value = data.indicator_value.strip()

    if not value:
        raise HTTPException(
            status_code=400,
            detail="Indicator value cannot be empty"
        )

    with engine.begin() as connection:

        result = connection.execute(
            text("""
                INSERT INTO threat_indicators
                (
                    indicator_type,
                    indicator_value,
                    threat_type,
                    severity,
                    confidence,
                    source,
                    description,
                    first_seen,
                    last_seen
                )
                VALUES
                (
                    :indicator_type,
                    :indicator_value,
                    :threat_type,
                    :severity,
                    :confidence,
                    :source,
                    :description,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                ON CONFLICT
                (
                    indicator_type,
                    indicator_value,
                    source
                )
                DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    is_active = TRUE,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING *
            """),
            {
                **data.model_dump(),
                "indicator_value": value
            }
        )

        record = result.mappings().one()

    return {
        "message": "Threat indicator saved",
        "indicator": dict(record)
    }


@app.get("/threat-intelligence/indicators")
def list_threat_indicators(
    indicator_type: str | None = None,
    active: bool | None = True,
    limit: int = Query(default=100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):

    conditions = []
    params = {"limit": limit}

    if indicator_type:

        conditions.append(
            "indicator_type = :indicator_type"
        )

        params["indicator_type"] = indicator_type.upper()

    if active is not None:

        conditions.append(
            "is_active = :active"
        )

        params["active"] = active

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions else ""
    )

    with engine.connect() as connection:

        result = connection.execute(
            text(f"""
                SELECT *
                FROM threat_indicators
                {where_clause}
                ORDER BY created_at DESC
                LIMIT :limit
            """),
            params
        )

        records = [
            dict(row)
            for row in result.mappings().all()
        ]

    return {
        "total": len(records),
        "indicators": records
    }


@app.get("/threat-intelligence/check")
def check_threat_indicator(
    indicator_value: str,
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):

    with engine.connect() as connection:

        record = connection.execute(
            text("""
                SELECT *
                FROM threat_indicators
                WHERE indicator_value = :value
                AND is_active = TRUE
                AND (
                    expires_at IS NULL
                    OR expires_at > CURRENT_TIMESTAMP
                )
                ORDER BY confidence DESC
                LIMIT 1
            """),
            {"value": indicator_value.strip()}
        ).mappings().first()

    if record is None:

        return {
            "indicator": indicator_value,
            "is_malicious": False,
            "message": "No active matching IOC found"
        }

    return {
        "indicator": indicator_value,
        "is_malicious": True,
        "threat": dict(record)
    }


@app.patch("/threat-intelligence/indicators/{indicator_id}/status")
def update_threat_indicator_status(
    indicator_id: int,
    is_active: bool,
    current_user=Depends(require_roles(["admin"]))
):

    with engine.begin() as connection:

        result = connection.execute(
            text("""
                UPDATE threat_indicators
                SET
                    is_active = :is_active,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = :indicator_id
                RETURNING id, indicator_value, is_active
            """),
            {
                "indicator_id": indicator_id,
                "is_active": is_active
            }
        ).mappings().first()

    if result is None:

        raise HTTPException(
            status_code=404,
            detail="Threat indicator not found"
        )

    return {
        "message": "Indicator status updated",
        **dict(result)
    }


# ============================================================
# PHASE 22 - IP REPUTATION API
# ============================================================

from backend.security.ip_reputation import check_ip_reputation


@app.get("/threat-intelligence/reputation/ip")
def get_ip_reputation(
    ip_address: str,
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    return check_ip_reputation(ip_address)

# ============================================================
# PHASE 22 - THREAT INTELLIGENCE FEED API
# ============================================================

from backend.security.feed_manager import import_feed


@app.post("/threat-intelligence/feeds/{source_name}/sync")
def sync_threat_feed(
    source_name: str,
    dry_run: bool = Query(True),
    current_user=Depends(
        require_roles(["admin"])
    )
):
    result = import_feed(
        source_name=source_name,
        dry_run=dry_run
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Feed import failed")
        )

    return result

# ============================================================
# PHASE 23 - HISTORICAL SECURITY ANALYTICS
# ============================================================

from backend.analytics.security_history import get_security_history


@app.get("/security/analytics/history")
def security_history_api(
    days: int = Query(30, ge=1, le=90),
    period: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    current_user=Depends(get_current_user)
):
    try:
        return get_security_history(
            days=days,
            period=period
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )
    except Exception:
        app_logger = get_app_logger()
        app_logger.exception("Historical security analytics failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve historical security analytics"
        )

# ============================================================
# PHASE 23 - SSH ATTACK TREND ANALYSIS
# ============================================================

from backend.analytics.security_history import get_ssh_attack_trends


@app.get("/security/analytics/attack-trends")
def ssh_attack_trends_api(
    days: int = Query(30, ge=1, le=90),
    current_user=Depends(get_current_user)
):
    try:
        return get_ssh_attack_trends(days=days)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception:
        app_logger = get_app_logger()
        app_logger.exception("SSH attack trend analysis failed")

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve SSH attack trends"
        )

# ============================================================
# PHASE 23 - PREDICTIVE SECURITY RISK
# ============================================================

from backend.analytics.predictive_risk import predict_security_risk


@app.get("/security/analytics/predictive-risk")
def predictive_security_risk_api(
    days: int = Query(30, ge=1, le=90),
    current_user=Depends(get_current_user)
):
    try:
        return predict_security_risk(days=days)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception:
        app_logger = get_app_logger()
        app_logger.exception("Predictive security risk failed")

        raise HTTPException(
            status_code=500,
            detail="Unable to calculate predictive security risk"
        )

from backend.analytics.anomaly_forecast import forecast_metric_anomalies


@app.get("/security/analytics/anomaly-forecast")
def anomaly_forecast_api(current_user=Depends(get_current_user)):
    try:
        return forecast_metric_anomalies()
    except Exception:
        app_logger = get_app_logger()
        app_logger.exception("Anomaly trend forecasting failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to forecast infrastructure anomalies"
        )

from backend.analytics.attack_pattern_predictor import predict_attack_patterns


@app.get("/security/analytics/attack-patterns")
def attack_pattern_prediction_api(
    days: int = Query(30, ge=1, le=90),
    current_user=Depends(get_current_user)
):
    try:
        return predict_attack_patterns(days=days)
    except Exception:
        app_logger = get_app_logger()
        app_logger.exception("Attack pattern prediction failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to predict SSH attack patterns"
        )

from backend.analytics.predictive_alerts import generate_predictive_alerts


@app.get("/security/analytics/predictive-alerts")
def predictive_alerts_api(
    days: int = Query(30, ge=1, le=90),
    current_user=Depends(get_current_user)
):
    try:
        return generate_predictive_alerts(days=days)
    except Exception:
        app_logger = get_app_logger()
        app_logger.exception("Predictive alert generation failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to generate predictive security alerts"
        )


# ============================================================
# PHASE 24 - FILE INTEGRITY MONITORING
# ============================================================

from backend.security.file_integrity import (
    ensure_fim_tables,
    create_baseline,
    scan_integrity,
    get_fim_events,
    get_fim_baselines
)


@app.post("/security/fim/baseline/{hostname}")
def fim_create_baseline(
    hostname: str,
    current_user=Depends(require_roles(["admin"]))
):
    try:
        ensure_fim_tables()
        return create_baseline(
            hostname,
            username=current_user.get("username", "admin")
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/security/fim/scan/{hostname}")
def fim_scan(
    hostname: str,
    current_user=Depends(
        require_roles(["admin", "analyst"])
    )
):
    try:
        ensure_fim_tables()
        return scan_integrity(hostname)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/security/fim/events")
def fim_events(
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_fim_tables()
    return get_fim_events(limit)


@app.get("/security/fim/baselines")
def fim_baselines(
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_fim_tables()
    return get_fim_baselines()


# ============================================================
# PHASE 25 - PROCESS AND SERVICE SECURITY MONITORING
# ============================================================

from backend.security.process_service_monitor import (
    ensure_phase25_tables,
    get_process_detections,
    get_service_changes,
    get_process_service_alerts,
    get_process_service_summary
)


@app.get("/security/process-services/summary")
def process_service_summary(
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    return get_process_service_summary()


@app.get("/security/process-services/detections")
def process_service_detections(
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    return get_process_detections(limit)


@app.get("/security/process-services/service-changes")
def process_service_changes(
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    return get_service_changes(limit)


@app.get("/security/process-services/alerts")
def process_service_alerts(
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    return get_process_service_alerts(limit)


# ============================================================
# PHASE 26 - NETWORK SECURITY MONITORING
# ============================================================

from backend.security.network_monitor import (
    ensure_phase26_tables,
    get_network_summary,
    get_network_interfaces,
    get_network_listeners,
    get_network_connections,
    get_network_alerts
)


@app.get("/security/network/summary")
def network_security_summary(
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_phase26_tables()
    return get_network_summary()


@app.get("/security/network/interfaces")
def network_security_interfaces(
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_phase26_tables()
    return get_network_interfaces(limit)


@app.get("/security/network/listeners")
def network_security_listeners(
    limit: int = Query(200, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_phase26_tables()
    return get_network_listeners(limit)


@app.get("/security/network/connections")
def network_security_connections(
    limit: int = Query(200, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_phase26_tables()
    return get_network_connections(limit)


@app.get("/security/network/alerts")
def network_security_alerts(
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    ensure_phase26_tables()
    return get_network_alerts(limit)


# ============================================================
# PHASE 27.1 - CENTRALIZED HOST INVENTORY API
# ============================================================

import ipaddress


class HostInventoryCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=100)
    ip_address: str = Field(min_length=1, max_length=50)
    username: str = Field(min_length=1, max_length=100)
    auth_method: str = Field(default="password")
    key_file: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=1000)


class HostInventoryUpdate(BaseModel):
    ip_address: str | None = Field(default=None, max_length=50)
    username: str | None = Field(default=None, max_length=100)
    auth_method: str | None = None
    key_file: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=1000)


class HostInventoryStatusUpdate(BaseModel):
    enabled: bool


def validate_inventory_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Invalid IP address"
        )


@app.get("/inventory/hosts")
def list_inventory_hosts(
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    with engine.connect() as connection:
        rows = connection.execute(text("""
            SELECT
                id,
                hostname,
                ip_address,
                username,
                auth_method,
                enabled,
                description,
                registration_source,
                registered_at,
                updated_at,
                last_seen
            FROM monitored_hosts
            ORDER BY hostname;
        """)).mappings().all()

    return {
        "total": len(rows),
        "hosts": [dict(row) for row in rows]
    }


@app.get("/inventory/hosts/{hostname}")
def get_inventory_host(
    hostname: str,
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    with engine.connect() as connection:
        row = connection.execute(text("""
            SELECT *
            FROM monitored_hosts
            WHERE hostname = :hostname;
        """), {
            "hostname": hostname
        }).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Host not found"
        )

    host = dict(row)
    host.pop("key_file", None)
    return host


@app.post("/inventory/hosts", status_code=201)
def register_inventory_host(
    request: HostInventoryCreate,
    current_user=Depends(
        require_roles(["admin"])
    )
):
    hostname = request.hostname.strip()
    username = request.username.strip()
    ip_address = request.ip_address.strip()
    auth_method = request.auth_method.strip().lower()

    if not hostname or not username:
        raise HTTPException(
            status_code=422,
            detail="Hostname and username cannot be empty"
        )

    if auth_method not in ("password", "key"):
        raise HTTPException(
            status_code=422,
            detail="auth_method must be password or key"
        )

    if auth_method == "key" and not request.key_file:
        raise HTTPException(
            status_code=422,
            detail="key_file is required for key authentication"
        )

    validate_inventory_ip(ip_address)

    with engine.begin() as connection:
        existing = connection.execute(text("""
            SELECT id
            FROM monitored_hosts
            WHERE hostname = :hostname;
        """), {
            "hostname": hostname
        }).first()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Hostname is already registered"
            )

        result = connection.execute(text("""
            INSERT INTO monitored_hosts (
                hostname,
                ip_address,
                username,
                auth_method,
                key_file,
                description,
                registration_source
            )
            VALUES (
                :hostname,
                :ip_address,
                :username,
                :auth_method,
                :key_file,
                :description,
                'manual'
            )
            RETURNING
                id,
                hostname,
                ip_address,
                username,
                auth_method,
                key_file,
                enabled,
                description,
                registration_source,
                registered_at;
        """), {
            "hostname": hostname,
            "ip_address": ip_address,
            "username": username,
            "auth_method": auth_method,
            "key_file": request.key_file,
            "description": request.description
        }).mappings().first()

    host = dict(result)
    host.pop("key_file", None)

    return {
        "message": "Host registered successfully",
        "host": host
    }


@app.patch("/inventory/hosts/{hostname}")
def update_inventory_host(
    hostname: str,
    request: HostInventoryUpdate,
    current_user=Depends(
        require_roles(["admin"])
    )
):
    updates = request.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided"
        )

    with engine.begin() as connection:
        existing = connection.execute(text("""
            SELECT *
            FROM monitored_hosts
            WHERE hostname = :hostname;
        """), {
            "hostname": hostname
        }).mappings().first()

        if not existing:
            raise HTTPException(
                status_code=404,
                detail="Host not found"
            )

        new_ip = updates.get(
            "ip_address",
            existing["ip_address"]
        )

        new_username = updates.get(
            "username",
            existing["username"]
        )

        new_auth = updates.get(
            "auth_method",
            existing["auth_method"]
        )

        new_key_file = updates.get(
            "key_file",
            existing["key_file"]
        )

        if new_ip is not None:
            validate_inventory_ip(new_ip)

        if new_username is not None and not new_username.strip():
            raise HTTPException(
                status_code=422,
                detail="Username cannot be empty"
            )

        if new_auth is not None:
            new_auth = new_auth.strip().lower()

        if new_auth not in ("password", "key"):
            raise HTTPException(
                status_code=422,
                detail="auth_method must be password or key"
            )

        if new_auth == "key" and not new_key_file:
            raise HTTPException(
                status_code=422,
                detail="key_file is required for key authentication"
            )

        allowed_fields = {
            "ip_address",
            "username",
            "auth_method",
            "key_file",
            "description"
        }

        assignments = ", ".join(
            f"{field} = :{field}"
            for field in updates
            if field in allowed_fields
        )

        updates["hostname"] = hostname

        connection.execute(text(f"""
            UPDATE monitored_hosts
            SET {assignments},
                updated_at = CURRENT_TIMESTAMP
            WHERE hostname = :hostname;
        """), updates)

        updated = connection.execute(text("""
            SELECT *
            FROM monitored_hosts
            WHERE hostname = :hostname;
        """), {
            "hostname": hostname
        }).mappings().first()

    host = dict(updated)
    host.pop("key_file", None)

    return {
        "message": "Host inventory updated",
        "host": host
    }


@app.patch("/inventory/hosts/{hostname}/status")
def update_inventory_host_status(
    hostname: str,
    request: HostInventoryStatusUpdate,
    current_user=Depends(
        require_roles(["admin"])
    )
):
    with engine.begin() as connection:
        result = connection.execute(text("""
            UPDATE monitored_hosts
            SET enabled = :enabled,
                updated_at = CURRENT_TIMESTAMP
            WHERE hostname = :hostname
            RETURNING hostname, ip_address, enabled, updated_at;
        """), {
            "hostname": hostname,
            "enabled": request.enabled
        }).mappings().first()

        if not result:
            raise HTTPException(
                status_code=404,
                detail="Host not found"
            )

    return {
        "message": "Host status updated",
        "host": dict(result)
    }


# ============================================================
# PHASE 27.2 - MULTI-SERVER FLEET OVERVIEW
# ============================================================

@app.get("/fleet/overview")
def get_fleet_overview(
    current_user=Depends(
        require_roles(["admin", "analyst", "viewer"])
    )
):
    with engine.connect() as connection:
        rows = connection.execute(text("""
            WITH latest_metrics AS (
                SELECT DISTINCT ON (hostname)
                    hostname,
                    ip_address,
                    cpu_usage,
                    memory_usage,
                    disk_usage,
                    collected_at
                FROM system_metrics
                ORDER BY hostname, collected_at DESC
            )
            SELECT
                h.hostname,
                h.ip_address,
                h.enabled,
                h.description,
                h.registered_at,
                lm.cpu_usage,
                lm.memory_usage,
                lm.disk_usage,
                lm.collected_at AS last_seen,
                CASE
                    WHEN h.enabled = FALSE THEN 'Disabled'
                    WHEN lm.collected_at IS NULL THEN 'No Data'
                    WHEN lm.collected_at < NOW() - INTERVAL '30 seconds'
                        THEN 'Stale'
                    WHEN lm.cpu_usage > 90
                      OR lm.memory_usage > 90
                      OR lm.disk_usage > 90
                        THEN 'Critical'
                    WHEN lm.cpu_usage > 70
                      OR lm.memory_usage > 70
                      OR lm.disk_usage > 70
                        THEN 'Warning'
                    ELSE 'Healthy'
                END AS status
            FROM monitored_hosts h
            LEFT JOIN latest_metrics lm
                ON lm.hostname = h.hostname
            ORDER BY h.hostname;
        """)).mappings().all()

    hosts = [dict(row) for row in rows]

    summary = {
        "total": len(hosts),
        "online": sum(
            host["status"] in ("Healthy", "Warning", "Critical")
            for host in hosts
        ),
        "healthy": sum(
            host["status"] == "Healthy" for host in hosts
        ),
        "warning": sum(
            host["status"] == "Warning" for host in hosts
        ),
        "critical": sum(
            host["status"] == "Critical" for host in hosts
        ),
        "stale": sum(
            host["status"] == "Stale" for host in hosts
        ),
        "no_data": sum(
            host["status"] == "No Data" for host in hosts
        ),
        "disabled": sum(
            host["status"] == "Disabled" for host in hosts
        )
    }

    return {
        "summary": summary,
        "hosts": hosts
    }
