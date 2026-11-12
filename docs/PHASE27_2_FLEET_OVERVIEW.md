# Phase 27.2 – Multi-Server Fleet Overview Dashboard

## Objective
Display all registered Linux servers in one authenticated dashboard.

## Backend
- Endpoint: GET /fleet/overview
- Uses monitored_hosts and latest system_metrics records.
- Calculates host status from enabled state, data freshness and resource thresholds.
- Returns fleet summary and per-host resource information.

## Frontend
- Fleet summary cards: Total, Online, Healthy, Warning and Critical.
- Individual host cards: hostname, IP, status, CPU, memory and disk.
- Last-seen timestamp.
- Hostname/IP search.
- Status filtering.
- Manual refresh.
- Automatic refresh every 10 seconds.
- Uses authenticated apiFetch and escapeHtml.

## Access Control
- Admin: read access.
- Analyst: read access.
- Viewer: read access.
- Unauthenticated requests: HTTP 401.

## Verification
- Fleet API: HTTP 200.
- Registered hosts returned: 2.
- Admin: PASS.
- Analyst: PASS.
- Viewer: PASS.
- Unauthenticated request: HTTP 401.
- Python compilation: PASS.
- JavaScript syntax check: PASS.
- Git whitespace check: PASS.

## Current Test Data
- attacker – 192.168.38.147
- prac-server – 192.168.38.145

Both hosts reported Healthy during the verification test.
