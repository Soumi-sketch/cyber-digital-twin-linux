import pandas as pd

from sklearn.ensemble import IsolationForest


def train_anomaly_model(data):

    if data.empty:
        raise ValueError(
            "No data available for ML training."
        )

    features = [
        "cpu_usage",
        "memory_usage",
        "disk_usage"
    ]

    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )

    model.fit(
        data[features]
    )

    return model


def predict_anomaly(model, data):

    features = [
        "cpu_usage",
        "memory_usage",
        "disk_usage"
    ]

    predictions = model.predict(
        data[features]
    )

    scores = model.decision_function(
        data[features]
    )

    result = data.copy()

    result["ml_prediction"] = predictions
    result["ml_score"] = scores

    result["is_ml_anomaly"] = (
        result["ml_prediction"] == -1
    )

    return result
