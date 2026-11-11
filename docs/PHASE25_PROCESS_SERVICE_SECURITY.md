# Phase 25 - Process and Service Security Monitoring

## Features
1. Remote process and service inventory.
2. Exact-name suspicious-process indicators and risk scoring.
3. systemd service-state change history.
4. Installed service-unit inventory and persistence-name indicators.
5. Persistent process/service alert records with severity.
6. RBAC-protected FastAPI read endpoints.
7. Dashboard summary, detections, service changes and alerts.
8. Automated validation and operational documentation.

## Collection
The scheduler runs process and service inventory every 60 seconds.
It reuses existing SSH connections and does not add work to the
five-second system-metrics collection interval.

## Detection
Process-name indicators are investigative signals, not proof of compromise.
Dual-use network tools are MEDIUM severity. No process is terminated.

## Service monitoring
The first unit-file scan establishes a baseline. Later state changes
are recorded. Inactive or disabled services are not automatically
classified as malicious.

## Safety
No automatic process termination, service disabling, firewall changes,
or external notifications are performed by this phase.

## API
- GET /security/process-services/summary
- GET /security/process-services/detections
- GET /security/process-services/service-changes
- GET /security/process-services/alerts

All endpoints require an authenticated admin, analyst, or viewer role.
