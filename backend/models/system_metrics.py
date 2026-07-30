from sqlalchemy import Column, Integer, String, Float, TIMESTAMP, text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class SystemMetrics(Base):
    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(100))
    cpu_usage = Column(Float)
    memory_usage = Column(Float)
    disk_usage = Column(Float)
    collected_at = Column(TIMESTAMP, server_default=text("CURRENT_TIMESTAMP"))
