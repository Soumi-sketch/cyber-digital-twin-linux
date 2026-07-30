import time

from backend.collector.remote_collector import collect_remote_data


while True:

    try:
        collect_remote_data()

        print("⏳ Waiting 5 seconds for next collection...")

    except Exception as e:

        print(f"❌ Collection failed: {e}")

    time.sleep(5)
