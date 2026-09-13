from sklearn.ensemble import IsolationForest


FEATURES = [
    "cpu_usage",
    "memory_usage",
    "disk_usage"
]


def train_anomaly_model(
    data,
    training_window=1000
):

    if data.empty:

        raise ValueError(
            "No data available for ML training."
        )


    training_data = data.tail(
        training_window
    ).copy()


    if len(training_data) < 20:

        raise ValueError(
            "Not enough data available for ML training."
        )


    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42
    )


    model.fit(
        training_data[FEATURES]
    )


    return model


def predict_anomaly(
    model,
    data
):

    predictions = model.predict(
        data[FEATURES]
    )


    scores = model.decision_function(
        data[FEATURES]
    )


    result = data.copy()


    result["ml_prediction"] = predictions


    result["ml_score"] = scores


    result["is_ml_anomaly"] = (
        result["ml_prediction"] == -1
    )


    return result
