import statistics


def detect_anomaly(values, current_value):
    """
    Detect whether the current value is unusual
    compared with historical values.

    Uses the Z-score method.
    """

    if len(values) < 5:
        return {
            "is_anomaly": False,
            "score": 0,
            "reason": "Not enough historical data"
        }

    mean = statistics.mean(values)
    std_dev = statistics.stdev(values)

    # Avoid division by zero
    if std_dev == 0:
        return {
            "is_anomaly": False,
            "score": 0,
            "reason": "No historical variation"
        }

    z_score = abs((current_value - mean) / std_dev)

    if z_score >= 3:
        status = "Anomaly"

    elif z_score >= 2:
        status = "Warning"

    else:
        status = "Normal"

    return {
        "is_anomaly": z_score >= 3,
        "score": round(z_score, 2),
        "status": status,
        "mean": round(mean, 2),
        "std_dev": round(std_dev, 2)
    }
