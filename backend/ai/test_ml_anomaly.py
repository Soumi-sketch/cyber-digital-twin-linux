import pandas as pd

from backend.database import engine

from backend.ai.ml_anomaly_detector import (
    train_anomaly_model,
    predict_anomaly
)


QUERY = """
SELECT
    hostname,
    cpu_usage,
    memory_usage,
    disk_usage,
    collected_at
FROM system_metrics
WHERE hostname = :hostname
  AND cpu_usage IS NOT NULL
  AND memory_usage IS NOT NULL
  AND disk_usage IS NOT NULL
ORDER BY collected_at ASC
"""


def load_host_data(hostname):

    from sqlalchemy import text

    with engine.connect() as connection:

        return pd.read_sql(
            text(QUERY),
            connection,
            params={
                "hostname": hostname
            }
        )

def main():

    hostname = "prac-server"

    print(
        f"Loading historical data for {hostname}..."
    )

    data = load_host_data(
        hostname
    )

    print(
        f"Samples loaded: {len(data)}"
    )

    if len(data) < 20:

        raise ValueError(
            "Not enough data for ML testing."
        )

    model = train_anomaly_model(
        data
    )

    latest = data.tail(
        10
    ).copy()

    result = predict_anomaly(
        model,
        latest
    )

    print()
    print(
        "Latest ML analysis:"
    )

    print(
        result[
            [
                "collected_at",
                "cpu_usage",
                "memory_usage",
                "disk_usage",
                "ml_score",
                "is_ml_anomaly"
            ]
        ].to_string(
            index=False
        )
    )


if __name__ == "__main__":

    main()
