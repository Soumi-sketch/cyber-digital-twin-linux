from sqlalchemy import text

from backend.database import engine
from backend.ai.anomaly_detector import detect_anomaly


def get_metric_values(column, limit=50):
    """
    Get recent historical values for one metric.
    """

    allowed_columns = {
        "cpu_usage",
        "memory_usage",
        "disk_usage"
    }

    if column not in allowed_columns:
        raise ValueError("Invalid metric column")

    with engine.connect() as connection:

        result = connection.execute(
            text(f"""
                SELECT {column}
                FROM system_metrics
                WHERE {column} IS NOT NULL
                ORDER BY collected_at DESC
                LIMIT :limit
            """),
            {"limit": limit}
        )

        rows = result.fetchall()

    return [float(row[0]) for row in rows]


def analyze_metric(column):
    """
    Analyze the latest metric against historical values.
    """

    values = get_metric_values(column)

    if not values:
        return {
            "metric": column,
            "status": "No Data"
        }

    current_value = values[0]

    # Use older values as the historical baseline
    historical_values = values[1:]

    result = detect_anomaly(
        historical_values,
        current_value
    )

    return {
        "metric": column,
        "current_value": current_value,
        **result
    }


def analyze_all_metrics():

    return {
        "cpu": analyze_metric("cpu_usage"),
        "memory": analyze_metric("memory_usage"),
        "disk": analyze_metric("disk_usage")
    }
