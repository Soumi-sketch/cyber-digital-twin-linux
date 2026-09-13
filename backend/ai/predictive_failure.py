import pandas as pd


def calculate_trend(values):

    if len(values) < 2:

        return 0.0

    first_value = values.iloc[0]

    last_value = values.iloc[-1]

    return float(
        last_value - first_value
    )


def calculate_rolling_average(
    values,
    window
):

    if len(values) < window:

        return float(
            values.mean()
        )

    return float(
        values.tail(window).mean()
    )


def calculate_volatility(
    values,
    window=30
):

    recent = values.tail(
        window
    )

    if len(recent) < 2:

        return 0.0

    return float(
        recent.std()
    )


def calculate_risk(
    cpu_current,
    memory_current,
    cpu_trend,
    memory_trend,
    cpu_average,
    memory_average,
    cpu_volatility,
    memory_volatility,
    cpu_max,
    memory_max
):

    risk_score = 0

    reasons = []


    # --------------------------------
    # Current CPU pressure
    # --------------------------------

    if cpu_current >= 80:

        risk_score += 30

        reasons.append(
            "CPU usage is critically high."
        )

    elif cpu_current >= 50:

        risk_score += 20

        reasons.append(
            "CPU usage is elevated."
        )

    elif cpu_current >= 30:

        risk_score += 10

        reasons.append(
            "CPU usage is moderately elevated."
        )


    # --------------------------------
    # Current memory pressure
    # --------------------------------

    if memory_current >= 80:

        risk_score += 30

        reasons.append(
            "Memory usage is critically high."
        )

    elif memory_current >= 75:

        risk_score += 20

        reasons.append(
            "Memory usage is elevated."
        )

    elif memory_current >= 70:

        risk_score += 10

        reasons.append(
            "Memory usage is moderately elevated."
        )


    # --------------------------------
    # CPU trend
    # --------------------------------

    if cpu_trend >= 20:

        risk_score += 20

        reasons.append(
            "CPU usage shows a strong upward trend."
        )

    elif cpu_trend >= 10:

        risk_score += 10

        reasons.append(
            "CPU usage is increasing."
        )


    # --------------------------------
    # Memory trend
    # --------------------------------

    if memory_trend >= 15:

        risk_score += 20

        reasons.append(
            "Memory usage shows a strong upward trend."
        )

    elif memory_trend >= 7:

        risk_score += 10

        reasons.append(
            "Memory usage is increasing."
        )


    # --------------------------------
    # CPU volatility
    # --------------------------------

    if cpu_volatility >= 20:

        risk_score += 15

        reasons.append(
            "CPU usage is highly volatile."
        )

    elif cpu_volatility >= 10:

        risk_score += 8

        reasons.append(
            "CPU usage volatility is elevated."
        )


    # --------------------------------
    # Memory volatility
    # --------------------------------

    if memory_volatility >= 10:

        risk_score += 15

        reasons.append(
            "Memory usage is highly volatile."
        )

    elif memory_volatility >= 5:

        risk_score += 8

        reasons.append(
            "Memory usage volatility is elevated."
        )


    # --------------------------------
    # Historical maximums
    # --------------------------------

    if cpu_max >= 90:

        risk_score += 10

        reasons.append(
            "CPU reached a critical historical level."
        )

    elif cpu_max >= 70:

        risk_score += 5

        reasons.append(
            "CPU reached a high historical level."
        )


    if memory_max >= 90:

        risk_score += 10

        reasons.append(
            "Memory reached a critical historical level."
        )

    elif memory_max >= 80:

        risk_score += 5

        reasons.append(
            "Memory reached a high historical level."
        )


    # --------------------------------
    # Historical baseline comparison
    # --------------------------------

    if cpu_current > cpu_average + 15:

        risk_score += 10

        reasons.append(
            "Current CPU usage is significantly above its recent baseline."
        )


    if memory_current > memory_average + 10:

        risk_score += 10

        reasons.append(
            "Current memory usage is significantly above its recent baseline."
        )


    # --------------------------------
    # Risk classification
    # --------------------------------

    if risk_score >= 70:

        status = "Critical"

    elif risk_score >= 50:

        status = "High"

    elif risk_score >= 25:

        status = "Warning"

    else:

        status = "Stable"


    return {
        "risk_score": min(
            risk_score,
            100
        ),
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


    cpu = data[
        "cpu_usage"
    ]

    memory = data[
        "memory_usage"
    ]


    # --------------------------------
    # Current values
    # --------------------------------

    cpu_current = float(
        cpu.iloc[-1]
    )

    memory_current = float(
        memory.iloc[-1]
    )


    # --------------------------------
    # Trends
    # --------------------------------

    cpu_trend = calculate_trend(
        cpu
    )

    memory_trend = calculate_trend(
        memory
    )


    # --------------------------------
    # Rolling averages
    # --------------------------------

    cpu_average = calculate_rolling_average(
        cpu,
        30
    )

    memory_average = calculate_rolling_average(
        memory,
        30
    )


    # --------------------------------
    # Volatility
    # --------------------------------

    cpu_volatility = calculate_volatility(
        cpu,
        30
    )

    memory_volatility = calculate_volatility(
        memory,
        30
    )


    # --------------------------------
    # Maximum values
    # --------------------------------

    cpu_max = float(
        cpu.max()
    )

    memory_max = float(
        memory.max()
    )


    # --------------------------------
    # Calculate risk
    # --------------------------------

    risk = calculate_risk(
        cpu_current=cpu_current,
        memory_current=memory_current,
        cpu_trend=cpu_trend,
        memory_trend=memory_trend,
        cpu_average=cpu_average,
        memory_average=memory_average,
        cpu_volatility=cpu_volatility,
        memory_volatility=memory_volatility,
        cpu_max=cpu_max,
        memory_max=memory_max
    )


    return {
        "cpu_current": round(
            cpu_current,
            2
        ),
        "memory_current": round(
            memory_current,
            2
        ),
        "cpu_trend": round(
            cpu_trend,
            2
        ),
        "memory_trend": round(
            memory_trend,
            2
        ),
        "cpu_average": round(
            cpu_average,
            2
        ),
        "memory_average": round(
            memory_average,
            2
        ),
        "cpu_volatility": round(
            cpu_volatility,
            2
        ),
        "memory_volatility": round(
            memory_volatility,
            2
        ),
        "cpu_max": round(
            cpu_max,
            2
        ),
        "memory_max": round(
            memory_max,
            2
        ),
        **risk
    }
