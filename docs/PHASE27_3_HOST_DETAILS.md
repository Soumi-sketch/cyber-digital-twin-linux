# Phase 27.3 – Individual Server Details and Drill-Down

## Objective
Provide a detailed view of each registered server from the Multi-Server Fleet Overview.

## Backend API
- GET /inventory/hosts/{hostname}
  - Returns registered host information.
- GET /inventory/hosts/{hostname}/metrics?limit=50
  - Returns recent CPU, memory and disk metrics.
  - Limit is restricted to a maximum of 100 records.
  - Returns HTTP 404 when the host is not registered.

## Frontend
- Added a View Details action to each fleet server card.
- Displays host registration information.
- Displays recent CPU, memory and disk history.
- Includes a Close Details action.
- Uses the existing authenticated API helper.
- Escapes dynamic text before rendering.

## Access control
Admin, Analyst and Viewer can read host details and metric history.
Write permissions remain governed by the existing inventory RBAC policy.

## Validation
- Python compilation passed.
- JavaScript syntax check passed.
- Git whitespace check passed.
- Admin, Analyst and Viewer each received HTTP 200 for both registered hosts.
- Dashboard details and metric history verified for both hosts.

## Scope note
SSH events are not attributed to individual monitored hosts in this feature because the current ssh_events schema does not contain a monitored-host identifier. Cross-server event correlation remains separate work.
