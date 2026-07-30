from backend.database import SessionLocal
from backend.models.system_metrics import SystemMetrics


def save_metrics(data):
    session = SessionLocal()

    metric = SystemMetrics(
        hostname=data["hostname"],
        ip_address=data["ip_address"],
        operating_system=data["operating_system"],
        kernel_version=data["kernel_version"],
        cpu_usage=data["cpu_usage"],
        memory_usage=data["memory_usage"],
        disk_usage=data["disk_usage"],
        uptime=data["uptime"]
    )

    session.add(metric)
    session.commit()
    session.close()
