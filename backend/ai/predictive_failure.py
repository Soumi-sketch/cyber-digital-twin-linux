import pandas as pd


def calculate_trend(values):

    if len(values) < 2:

        return 0.0

    first_value = values.iloc[0]
    last_value = values.iloc[-1]

    return float(
        last_value - first_value
    )


def calculate_risk(
    cpu_trend,
    memory_trend,
    disk_trend,
    cpu_max,
    memory_max,
    disk_max
):

    risk_score = 0

    reasons = []

    # CPU trend

    if cpu_trend >= 20:

        risk_score += 30

        reasons.append(
            "CPU usage shows a strong upward trend."
        )

    elif cpu_trend >= 10:

        risk_score += 15

        reasons.append(
            "CPU usage is increasing."
        )


    # Memory trend

    if memory_trend >= 15:

        risk_score += 30

        reasons.append(
            "Memory usage shows a strong upward trend."
        )

    elif memory_trend >= 7:

        risk_score += 15

        reasons.append(
            "Memory usage is increasing."
        )


    # Disk usage

    if disk_trend >= 15:

        risk_score += 30

        reasons.append(
            "Disk usage is increasing rapidly."
        )

    elif disk_trend >= 7:

        risk_score += 15

        reasons.append(
            "Disk usage is increasing."
        )


    # Absolute resource thresholds

    if cpu_max >= 90:

        risk_score += 20

        reasons.append(
            "CPU usage reached a critical level."
        )


    if memory_max >= 90:

        risk_score += 20

        reasons.append(
            "Memory usage reached a critical level."
        )


    if disk_max >= 90:

        risk_score += 20

        reasons.append(
            "Disk usage reached a critical level."
        )


    if risk_score >= 50:

        status = "Critical"

    elif risk_score >= 25:

        status = "Warning"

    else:

        status = "Stable"


    return {
        "risk_score": risk_score,
        "status": status,
        "reasons": reasons
    }


def predict_failure(data):

    if data.empty:

        return {
            "status": "No Data",
            "risk_score": 0,
            "reasons": []
        }


    cpu_trend = calculate_trend(
        data["cpu_usage"]
    )

    memory_trend = calculate_trend(
        data["memory_usage"]
    )

    disk_trend = calculate_trend(
        data["disk_usage"]
    )


    cpu_max = data["cpu_usage"].max()

    memory_max = data["memory_usage"].max()

    disk_max = data["disk_usage"].max()


    risk = calculate_risk(
        cpu_trend,
        memory_trend,
        disk_trend,
        cpu_max,
        memory_max,
        disk_max
    )


    return {
        "cpu_trend": round(
            cpu_trend,
            2
        ),

        "memory_trend": round(
            memory_trend,
            2
        ),

        "disk_trend": round(
            disk_trend,
            2
        ),

        "cpu_max": round(
            float(cpu_max),
            2
        ),

        "memory_max": round(
            float(memory_max),
            2
        ),

        "disk_max": round(
            float(disk_max),
            2
        ),

        **risk
    }
