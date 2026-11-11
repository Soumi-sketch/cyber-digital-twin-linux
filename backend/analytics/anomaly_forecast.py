import statistics

from sqlalchemy import text
from backend.database import engine


def forecast_metric_anomalies():

    with engine.connect() as connection:

        rows = connection.execute(text("""
            SELECT
                DATE_TRUNC('day', collected_at) AS metric_day,
                AVG(cpu_usage) AS cpu_avg,
                AVG(memory_usage) AS memory_avg,
                AVG(disk_usage) AS disk_avg
            FROM system_metrics
            WHERE collected_at >=
                CURRENT_TIMESTAMP - INTERVAL '30 days'
            GROUP BY DATE_TRUNC('day', collected_at)
            ORDER BY metric_day
        """)).mappings().all()

    if len(rows) < 6:
        return {
            "status": "INSUFFICIENT_DATA",
            "message": "At least 6 observed days are required",
            "available_days": len(rows)
       }

    metrics = {
        "cpu": "cpu_avg",
        "memory": "memory_avg",
        "disk": "disk_avg"
    }

    forecasts = {}

    for metric, column in metrics.items():

        values = [
            float(row[column])
            for row in rows
            if row[column] is not None
        ]

        if len(values) < 6:
            forecasts[metric] = {
                "status": "INSUFFICIENT_DATA",
                "available_days": len(values),
                "required_days": 6
            }
            continue

        previous_values = values[-6:-3]
        current_values = values[-3:]

        previous_avg = statistics.mean(previous_values)
        current_avg = statistics.mean(current_values)

        change = current_avg - previous_avg

        predicted_avg = max(
            0,
            min(100, current_avg + change)
        )

        if change > 2:
            direction = "INCREASING"
        elif change < -2:
            direction = "DECREASING"
        else:
            direction = "STABLE"

        std_dev = statistics.stdev(previous_values)

        if std_dev > 0:
            threshold = previous_avg + (2 * std_dev)
            anomaly_forecast = predicted_avg > threshold
        else:
            threshold = None
            anomaly_forecast = False

        forecasts[metric] = {
            "previous_3_observation_average": round(previous_avg, 2),
            "current_3_observation_average": round(current_avg, 2),
            "change": round(change, 2),
            "direction": direction,
            "predicted_next_observation_average": round(predicted_avg, 2),
            "historical_anomaly_threshold": (
                round(threshold, 2)
                if threshold is not None else None
            ),
            "predicted_anomaly": anomaly_forecast
        }

    return {
        "analysis_lookback_days": 30,
        "comparison": "Latest 3 observed days vs previous 3 observed days",
        "forecast_horizon": "Next daily observation",        "metrics": forecasts,
        "method": "3-day observed average trend projection with historical standard deviation"
    }

