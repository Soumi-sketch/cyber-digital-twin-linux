import time

from backend.config.hosts import HOSTS

from backend.collector.remote_collector import (
    create_ssh_client,
    collect_remote_data
)

from backend.collector.ssh_collector import (
    collect_ssh_events
)

clients = {}


while True:

    for host in HOSTS:

        host_name = host["name"]

        try:

            # ------------------------------------------------
            # CHECK / CREATE SSH CONNECTION
            # ------------------------------------------------

            client = clients.get(host_name)

            if (
                client is None
                or client.get_transport() is None
                or not client.get_transport().is_active()
            ):

                print(
                    f"🔌 Creating SSH connection to "
                    f"{host_name} ({host['host']})..."
                )

                if client:

                    try:
                        client.close()
                    except Exception:
                        pass

                client = create_ssh_client(host)

                clients[host_name] = client

                print(
                    f"✅ SSH connection established: "
                    f"{host_name}"
                )

            # ------------------------------------------------
            # COLLECT SYSTEM METRICS
            # ------------------------------------------------

            collect_remote_data(client)

            print(
                f"📊 Metrics collected: {host_name}"
            )

            # ------------------------------------------------
            # COLLECT SSH SECURITY EVENTS
            # ------------------------------------------------

            collect_ssh_events(
                client,
                host["name"],
                host["host"]
            )

            print(
                f"🔐 SSH events checked: {host_name}"
            )

        except Exception as e:

            print(
                f"❌ Collection failed for "
                f"{host_name}: {e}"
            )

            client = clients.get(host_name)

            if client:

                try:
                    client.close()
                except Exception:
                    pass

            clients[host_name] = None

    print("⏳ Waiting 5 seconds for next collection...")

    time.sleep(5)
