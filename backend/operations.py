from backend.database import SessionLocal
from backend.models.system_metrics import SystemMetrics

def save_metrics(data):
    session = SessionLocal()

    metric = SystemMetrics(
        hostname=data["hostname"],
        cpu_usage=data["cpu_usage"],
        memory_usage=data["memory_usage"],
        disk_usage=data["disk_usage"]
    )

    session.add(metric)
    session.commit()
    session.close()
