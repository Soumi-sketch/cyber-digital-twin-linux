import time

from backend.collector.remote_collector import collect_remote_data
from backend.collector.ssh_collector import collect_ssh_events


while True:

    try:
        # System metrics
        collect_remote_data()

        # SSH security events
        collect_ssh_events()

        print("⏳ Waiting 5 seconds for next collection...")

    except Exception as e:

        print(f"❌ Collection failed: {e}")

    time.sleep(5)
