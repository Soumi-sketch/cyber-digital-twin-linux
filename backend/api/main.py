from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from backend.database import engine


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
