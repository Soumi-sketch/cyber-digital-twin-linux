# Phase 27.5 – Cross-Server Health and Resource Comparison

## Objective
Compare the health and resource utilization of multiple monitored Linux servers from one centralized dashboard.

## Implemented Features
1. Side-by-side CPU utilization comparison.
2. Side-by-side memory utilization comparison.
3. Side-by-side disk utilization comparison.
4. Highest CPU usage ranking.
5. Highest memory usage ranking.
6. Highest disk usage ranking.
7. Fleet health summary using the existing fleet overview API.
8. Responsive comparison chart and ranking display.

## Backend
Endpoint: `GET /fleet/overview`

The endpoint returns:
- Fleet summary counts.
- Registered host information.
- Latest CPU, memory and disk metrics.
- Host health status.
- Last metric collection timestamp.

## Frontend
Files:
- `frontend/index.html`
- `frontend/app.js`
- `frontend/style.css`

The dashboard uses Chart.js to display grouped resource comparison bars and shows the highest-usage server for each resource.

## Access Control
The fleet overview endpoint requires authentication.

| Account role | Expected result |
|---|---|
| Unauthenticated | HTTP 401 |
| Admin | HTTP 200 |
| Analyst | HTTP 200 |
| Viewer | HTTP 200 |

All three authorized roles can read fleet comparison data.

## Verification
- Both `prac-server` and `attacker` appeared in the dashboard comparison chart.
- Admin, analyst and viewer API requests returned HTTP 200.
- The unauthenticated request returned HTTP 401.
- Each authorized role received fleet data for two hosts.
- Both hosts reported Healthy during testing.
- JavaScript syntax, Python compilation and Git whitespace checks passed.

## Result
Phase 27.5 implementation and verification are complete, pending final Git commit, push and VMware snapshot.
