# Phase 27.1 – Centralized Host Inventory

## Objective
Create a centralized database-backed inventory of monitored Linux hosts.

## Database
Table: `monitored_hosts`

Fields:
- id
- hostname (unique)
- ip_address
- username
- auth_method
- key_file
- enabled
- description
- registration_source
- registered_at
- updated_at
- last_seen

Existing hosts migrated from the static configuration:
- prac-server – 192.168.38.145
- attacker – 192.168.38.147

SSH passwords and private-key contents are not stored in this inventory table.

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | /inventory/hosts | List registered hosts |
| GET | /inventory/hosts/{hostname} | View one host |
| POST | /inventory/hosts | Register a host |
| PATCH | /inventory/hosts/{hostname} | Update host details |
| PATCH | /inventory/hosts/{hostname}/status | Enable or disable a host |

## Role-Based Access Control

| Operation | Admin | Analyst | Viewer |
|---|---|---|---|
| List hosts | Allowed | Allowed | Allowed |
| View host | Allowed | Allowed | Allowed |
| Register host | Allowed | Denied | Denied |
| Update host | Allowed | Denied | Denied |
| Change host status | Allowed | Denied | Denied |

## Validation
- IP address validation
- Duplicate hostname protection
- Authentication required
- Admin-only write operations
- Temporary test host cleanup

## Test Results
- RBAC tests: 16/16 passed
- Duplicate hostname: HTTP 409 passed
- Invalid IP address: HTTP 422 passed
- Read-response security checks: 6/6 passed
- Create/update response security checks: 2/2 passed
- Total recorded checks: 26 passed
- Python compilation: passed
- Git whitespace check: passed

## Current Scope
This feature provides centralized host registration and inventory APIs.
Dynamic integration of registered hosts into the continuous collector is a
separate implementation step in the multi-server expansion.
