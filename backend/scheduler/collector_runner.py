import time
import logging

from backend.config.hosts import HOSTS

from backend.collector.remote_collector import (
    create_ssh_client,
    collect_remote_data
)

from backend.collector.ssh_collector import (
    collect_ssh_events
)

from backend.security.alert_engine import (
    process_new_ssh_events
)

from backend.security.incident_escalation_manager import (
    process_incident_escalations
)

from backend.security.incident_reminder_manager import (
    process_incident_reminders
)

# ------------------------------------------------
# CONFIGURE LOGGING
# ------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)

logger = logging.getLogger("cyber_collector")


# ------------------------------------------------
# SSH CLIENT STORAGE
# ------------------------------------------------

clients = {}


# ------------------------------------------------
# CONTINUOUS COLLECTION LOOP
# ------------------------------------------------

while True:

    for host in HOSTS:

        host_name = host["name"]

        try:

            # ----------------------------------------
            # CHECK / CREATE SSH CONNECTION
            # ----------------------------------------

            client = clients.get(host_name)

            if (
                client is None
                or client.get_transport() is None
                or not client.get_transport().is_active()
            ):

                logger.info(
                    "Creating SSH connection to %s (%s)",
                    host_name,
                    host["host"]
                )

                if client:

                    try:
                        client.close()
                    except Exception:
                        logger.exception(
                            "Error closing old connection to %s",
                            host_name
                        )

                client = create_ssh_client(host)

                clients[host_name] = client

                logger.info(
                    "SSH connection established: %s",
                    host_name
                )

            # ----------------------------------------
            # COLLECT SYSTEM METRICS
            # ----------------------------------------

            collect_remote_data(client)

            logger.info(
                "Metrics collected: %s",
                host_name
            )

            # ----------------------------------------
            # COLLECT SSH SECURITY EVENTS
            # ----------------------------------------

            new_event_ids = collect_ssh_events(
                client,
                host["name"],
                host["host"]
            )

            logger.info(
                "SSH events checked: %s | New events: %d",
                host_name,
                len(new_event_ids or [])
            )

            # ----------------------------------------
            # PROCESS NEW SECURITY ALERTS
            # ----------------------------------------

            if new_event_ids:

                try:
                    alert_results = process_new_ssh_events(
                        new_event_ids
                    )

                    logger.info(
                        "Security alert processing completed: %s | Results: %d",
                        host_name,
                        len(alert_results)
                    )

                except Exception:
                    logger.exception(
                        "Security alert processing failed for %s",
                        host_name
                    )

        except Exception:

            logger.exception(
                "Collection failed for %s",
                host_name
            )

            client = clients.get(host_name)

            if client:

                try:
                    client.close()
                except Exception:
                    logger.exception(
                        "Error closing failed connection to %s",
                        host_name
                    )

            clients[host_name] = None

    # ----------------------------------------
    # PROCESS UNRESOLVED INCIDENT ESCALATIONS
    # ----------------------------------------

    try:

        escalation_results = process_incident_escalations()

        if escalation_results:

            logger.info(
                "Incident escalation checks completed | Results: %d",
                len(escalation_results)
            )

            for result in escalation_results:
                logger.info(
                    "Escalation result: %s",
                    result
                )

    except Exception:

        logger.exception(
            "Incident escalation processing failed"
        )

    # ----------------------------------------
    # PROCESS INCIDENT ASSIGNMENT REMINDERS
    # ----------------------------------------

    try:

        reminder_results = process_incident_reminders()

        if reminder_results:

            logger.info(
                "Incident reminder processing completed | Results: %d",
                len(reminder_results)
            )

            for result in reminder_results:

                logger.info(
                    "Reminder result: %s",
                    result
                )

    except Exception:

        logger.exception(
            "Incident reminder processing failed"
        )

    logger.info(
        "Waiting 5 seconds for next collection..."
    )

    time.sleep(5)
