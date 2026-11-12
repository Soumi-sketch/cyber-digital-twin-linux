# Phase 27.8 - Fleet Alert Aggregation and RBAC

## Objective
Provide one fleet-wide view of security alerts from SSH,
process/service monitoring and network monitoring.

## Implementation
- Backend: backend/security/fleet_alert_engine.py
- API: GET /fleet/security-alerts?limit=200
- Frontend: Fleet-Wide Security Alerts panel

## Alert sources

### SSH
Uses the existing SSH risk engine and its scoring rules.
The fleet aggregator retrieves up to 500 recent FAILED_LOGIN
and INVALID_USER event IDs and analyzes them using the existing
risk engine.

Only events with risk scores of 50 or higher are included:
- HIGH: score 50-79
- CRITICAL: score 80-100

Host attribution uses target_hostname and target_ip from
ssh_events, not the attacker's source IP.

### Process/service
Uses get_process_service_alerts() from the process/service
monitoring module.

### Network
Uses get_network_alerts() from the network monitoring module.

## API response
The response includes:
- Total alerts
- Critical, High, Medium and Low counts
- Affected host count
- Source counts
- Severity distribution
- Combined alert records
- Generation timestamp

Alerts are sorted by event time and limited by the API limit
parameter (1-500).

## RBAC
Admin: Read fleet alerts.
Analyst: Read fleet alerts.
Viewer: Read fleet alerts.

## Verification results
| Test | Result |
|---|---|
| Fleet alert engine import | PASS |
| Python compileall | PASS |
| JavaScript syntax check | PASS |
| Git whitespace check | PASS |
| Admin API access | HTTP 200 |
| Analyst API access | HTTP 200 |
| Viewer API access | HTTP 200 |
| Dashboard rendering | PASS |
| Phase 27 API regression | HTTP 200 on all 8 tested endpoints |

## Observed data at verification
- Total alerts: 19
- HIGH: 18
- CRITICAL: 1
- Affected hosts: 1
- SSH alerts: 19
- Process/service alerts: 0
- Network alerts: 0

The observed SSH alerts are historical records. Their timestamps
include August and September 2026. They must not be interpreted
as active attacks without checking current telemetry.

## Limitations
- Process/service and network alert tables contained no records
  during this verification.
- SSH aggregation is limited to the latest 500 failed/invalid
  login event IDs.
- The existing SSH risk engine's scoring and threat enrichment
  behavior is retained.
- The endpoint aggregates and displays alerts; it does not itself
  execute incident response actions or modify alert records.
