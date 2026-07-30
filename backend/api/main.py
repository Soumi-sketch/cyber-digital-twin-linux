from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from backend.database import engine

app = FastAPI(
    title="AI Powered Cyber Digital Twin",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "Welcome to AI Powered Cyber Digital Twin"
    }


@app.get("/metrics")
def get_metrics():

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT *
            FROM system_metrics
            ORDER BY collected_at DESC;
        """))

        return result.mappings().all()


@app.get("/hosts")
def get_hosts():

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT DISTINCT hostname, ip_address
            FROM system_metrics
            ORDER BY hostname;
        """))

        return result.mappings().all()


@app.get("/health")
def get_health():

    with engine.connect() as connection:

        result = connection.execute(text("""
            SELECT hostname,
                   cpu_usage,
                   memory_usage,
                   disk_usage
            FROM system_metrics
            ORDER BY collected_at DESC;
        """))

        rows = result.mappings().all()

    output = []

    for row in rows:

        if row["cpu_usage"] > 90 or row["memory_usage"] > 90 or row["disk_usage"] > 90:
            status = "Critical"

        elif row["cpu_usage"] > 70 or row["memory_usage"] > 70 or row["disk_usage"] > 70:
            status = "Warning"

        else:
            status = "Healthy"

        output.append({
            "hostname": row["hostname"],
            "status": status,
            "cpu_usage": row["cpu_usage"],
            "memory_usage": row["memory_usage"],
            "disk_usage": row["disk_usage"]
        })

    return output
