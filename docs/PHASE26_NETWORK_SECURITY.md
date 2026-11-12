# Phase 26 — Network Security Monitoring

## Features
1. Remote network interface and IP inventory.
2. Listening TCP/UDP socket inventory.
3. Active TCP/UDP connection inventory.
4. Configured risky-port detection.
5. Risk-scored network security alerts.
6. PostgreSQL history with seven-day inventory retention.
7. RBAC-protected FastAPI endpoints.
8. Dashboard integration and validation.

## Collection
The existing Paramiko SSH sessions are reused. The collector runs every
120 seconds against configured monitored hosts.

Commands:
- `ip -j address show`
- `ss -H -lntup`
- `ss -H -tunap`

No firewall changes, connection termination, or automatic blocking occur.

## Risk indicators
The monitor checks configured ports associated with insecure services,
remote-access tools, exposed management APIs, and suspicious listeners.
A port match is a heuristic indicator, not proof of compromise.

## API
- `GET /security/network/summary`
- `GET /security/network/interfaces`
- `GET /security/network/listeners`
- `GET /security/network/connections`
- `GET /security/network/alerts`

All endpoints require an authenticated admin, analyst, or viewer role.

## Database tables
- `network_interfaces`
- `network_listeners`
- `network_connections`
- `network_security_alerts`

Inventory history is retained for seven days. Security alerts are retained
for audit purposes.

## Limitations
- Socket process names depend on permissions and installed `ss` tooling.
- Connection inventory is capped at 500 entries per host per scan.
- Port-based indicators require analyst verification.
- This is host-level network visibility, not full packet capture or IDS.
