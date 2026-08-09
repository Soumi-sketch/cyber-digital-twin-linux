import time

from backend.collector.remote_collector import (
    create_ssh_client,
    collect_remote_data
)

from backend.collector.ssh_collector import (
    collect_ssh_events
)


client = None


while True:

    try:

        # Create SSH connection only when needed.
        if client is None or client.get_transport() is None or not client.get_transport().is_active():

            print("🔌 Creating SSH connection...")

            if client:
                try:
                    client.close()
                except Exception:
                    pass

            client = create_ssh_client()

            print("✅ SSH connection established.")

        # Collect system metrics.
        collect_remote_data(client)

        # Collect SSH security events using the same connection.
        collect_ssh_events(client)

        print("⏳ Waiting 5 seconds for next collection...")

    except Exception as e:

        print(f"❌ Collection failed: {e}")

        if client:
            try:
                client.close()
            except Exception:
                pass

        client = None

    time.sleep(5)
