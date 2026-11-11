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

from backend.security.file_integrity import (
    get_fim_baselines,
    scan_integrity
)

# ------------------------------------------------
from backend.security.process_service_monitor import (
    ensure_phase25_tables,
    monitor_host_process_services
)

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

last_fim_scan = 0
last_process_service_scan = 0


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

    # ----------------------------------------
    # AUTOMATED FIM SCAN - EVERY 60 SECONDS
    # ----------------------------------------

    if time.monotonic() - last_fim_scan >= 60:
        last_fim_scan = time.monotonic()

        try:
            baselines = get_fim_baselines()
            monitored_hosts = sorted({
                item["hostname"] for item in baselines
            })

            for hostname in monitored_hosts:
                try:
                    result = scan_integrity(hostname)
                    logger.info(
                        "Scheduled FIM scan: %s | Checked: %d | Changes: %d",
                        hostname,
                        result["files_checked"],
                        result["changes_detected"]
                    )

                    for event in result["events"]:
                        logger.warning(
                            "FIM ALERT: %s | %s | %s",
                            hostname,
                            event["event"],
                            event["file"]
                        )

                except Exception:
                    logger.exception(
                        "Scheduled FIM scan failed for %s",
                        hostname
                    )

        except Exception:
            logger.exception("Scheduled FIM baseline lookup failed")

    logger.info(
        "Waiting 5 seconds for next collection..."
    )


    # ----------------------------------------
    # PHASE 25 - PROCESS/SERVICE SCAN EVERY 60 SECONDS
    # ----------------------------------------

    if time.monotonic() - last_process_service_scan >= 60:
        last_process_service_scan = time.monotonic()

        try:
            ensure_phase25_tables()

            for host_name, client in list(clients.items()):
                if client is None:
                    continue

                try:
                    result = monitor_host_process_services(host_name, client)
                    logger.info(
                        "Phase 25 scan: %s | Processes: %d | Services: %d | Detections: %d",
                        host_name,
                        result["processes_collected"],
                        result["services_collected"],
                        result["detections"]
                    )
                except Exception:
                    logger.exception(
                        "Phase 25 monitoring failed for %s",
                        host_name
                    )

        except Exception:
            logger.exception("Phase 25 monitoring initialization failed")

    time.sleep(5)
