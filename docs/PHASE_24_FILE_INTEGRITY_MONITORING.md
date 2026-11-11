# Phase 24 – File Integrity Monitoring (FIM)

## 1. Objective
Detect unauthorized changes to important Linux configuration and security files using SHA-256 hashes.

## 2. Monitored Files
- /etc/passwd
- /etc/group
- /etc/shadow
- /etc/gshadow
- /etc/sudoers
- /etc/ssh/sshd_config
- /etc/hosts
- /etc/fstab

## 3. Core Implementation
- Creates and stores file hash baselines in PostgreSQL.
- Uses Paramiko SSH to scan the monitored Linux host remotely.
- Compares current SHA-256 hashes against stored baselines.
- Records detected modifications and deletions in the fim_events table.
- Does not automatically update baselines after detecting changes.

## 4. API Endpoints
- POST /security/fim/baseline/{hostname}
- POST /security/fim/scan/{hostname}
- GET /security/fim/events
- GET /security/fim/baselines

## 5. Role-Based Access
- Admin: create baselines and run scans.
- Analyst: run scans.
- Viewer: view baselines and events.

## 6. Automated Scanning
The cyber-collector service runs FIM scans every 60 seconds for hosts with stored baselines. It logs the number of files checked and detected changes.

The existing system metrics collector continues running every 5 seconds.

## 7. Validation
- Created a baseline for the monitored host.
- Modified a temporary test file and detected the change.
- Confirmed a HIGH-severity MODIFIED event was recorded.
- Confirmed the baseline remained unchanged.
- Verified scheduled scans approximately 60 seconds apart.
- Latest scheduled scans checked 8 files and detected 0 changes.

## 8. Current Scope and Limitations
- Monitoring is limited to the configured file list.
- Arbitrary new files are not automatically discovered.
- Detection depends on the monitored host being reachable over SSH.
- Baseline changes require an authorized baseline operation.

## 9. Result
Core remote file integrity monitoring, event recording, dashboard reporting, and automated 60-second scanning are implemented and validated.
