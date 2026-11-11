# Phase 24 — File Integrity Monitoring (FIM)

## Overview
The Cyber Digital Twin includes remote Linux File Integrity Monitoring (FIM).
It uses SSH to collect SHA-256 hashes and directory inventory from monitored
hosts, compares them with stored baselines, records integrity events, and
integrates severity-based alerts with the existing security alert engine.

## Feature 1 — File and directory monitoring
Monitored explicit files:
- /etc/passwd
- /etc/group
- /etc/shadow
- /etc/gshadow
- /etc/sudoers
- /etc/ssh/sshd_config
- /etc/hosts
- /etc/fstab

Recursively monitored directories:
- /etc/ssh
- /etc/sudoers.d
- /etc/cron.d

Directories are represented by a stable directory marker. Regular files
are represented by SHA-256 hashes. Symbolic links are not followed.

## Feature 2 — SHA-256 hashing and baseline storage
The FIM module calculates SHA-256 hashes for monitored files and stores
baselines in PostgreSQL `fim_baselines`, including hostname, path,
hash, update time, and administrator identity.

Baseline creation is an explicit operation. A detected change does not
automatically modify the baseline.

## Feature 3 — Change detection
The scanner compares the current remote inventory with the stored baseline:
- CREATED: new file or directory; HIGH severity.
- MODIFIED: changed file content; HIGH severity.
- DELETED: previously baselined file or directory is missing; CRITICAL severity.

Events are recorded in `fim_events`, with event type, path, severity,
old/new hashes, and detection timestamp. Duplicate unchanged observations
are suppressed by a stable event key.

## Feature 4 — Scheduled integrity scanning
The continuous collector performs scheduled FIM scans every 60 seconds
for hosts with stored FIM baselines. Scan outcomes are written to the
collector log. Manual scans are also available through the API.

## Feature 5 — Severity-based alert integration
New HIGH and CRITICAL FIM events are passed to the existing security
alert engine. FIM alert types use the `FIM_` prefix. HIGH events use
risk score 70 and CRITICAL events use risk score 95.

Validation intercepted notification delivery; no real email or Telegram
notifications were sent during tests.

## Feature 6 — Dashboard integration
The dashboard provides:
- Baseline creation (administrator).
- Manual integrity scan (administrator/analyst).
- Baseline inventory and SHA-256 values.
- Integrity event history and severity.
- Refresh controls.

## Feature 7 — Audit history and change tracking
Integrity events are retained in PostgreSQL and exposed through:
- `GET /security/fim/baselines`
- `GET /security/fim/events?limit=100`

The dashboard displays event history with hostname, path, event type,
severity, and detection timestamp.

## Feature 8 — Testing and validation
Validation performed against `prac-server`:
- Baseline creation and clean scan.
- File and directory creation detection: HIGH.
- File modification detection: HIGH.
- File and directory deletion detection: CRITICAL.
- HIGH and CRITICAL alert-engine integration using a notification capture
  function to avoid sending real messages.
- Dashboard baseline and event-history display.
- Scheduled scan interval verified in collector logs.
- Production cleanup verified: 25 discovered objects, 25 baselines,
  and no temporary validation objects.

Syntax checks:
- Python compilation for FIM, scheduler, and API modules.
- JavaScript syntax check for `frontend/app.js`.
- `git diff --check`.

## API access and permissions
- `POST /security/fim/baseline/{hostname}` — administrator.
- `POST /security/fim/scan/{hostname}` — administrator and analyst.
- `GET /security/fim/events?limit=100` — authenticated roles.
- `GET /security/fim/baselines` — authenticated roles.

## Operational notes
- Run the controller and API from the project virtual environment.
- Ensure monitored hosts are reachable over SSH with the configured
  credentials and trusted host keys.
- Review integrity events before approving a new baseline.
- Treat unexpected CRITICAL deletion events as high-priority incidents.
- FIM scope is limited to the configured files and directory trees;
  it is not a full filesystem-wide integrity scanner.
