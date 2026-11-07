# PostgreSQL Database Security Audit Report

**Project:** AI-Powered Cyber Digital Twin for Linux Infrastructure  
**Phase:** 16.9.6 — Database Security Audit Report  
**Database:** cyber_digital_twin  
**PostgreSQL Version:** 16.13  
**Audit Extension:** pgaudit 16.0  
**Audit Date:** 7 November 2026  
**Status:** Completed

---

## 1. Executive Summary

A security audit was performed on the PostgreSQL database used by the Cyber Digital Twin project.

The audit evaluated database access controls, role privileges, audit logging, backup automation, backup file permissions, integrity verification, and database restoration.

The implemented controls were tested using PostgreSQL commands, audit logs, systemd service checks, checksum verification, and a temporary database restoration test.

## 2. Database Security Configuration

The following security settings were verified:

| Security Control | Configuration |
|---|---|
| Audit extension | pgaudit |
| Connection logging | Enabled |
| Disconnection logging | Enabled |
| Audit logging | WRITE, DDL, ROLE |
| Sensitive-table read auditing | Enabled |
| Audit parameter logging | Disabled |
| Audit statement logging | Once |

The pgaudit extension was successfully initialized and verified.

## 3. Database Least-Privilege Access

The following database roles were examined:

| Role | Login | Superuser | Purpose |
|---|---|---|---|
| postgres | Yes | Yes | Database administration |
| cyberuser | Yes | No | Application database access |
| cyber_backup | Yes | No | Database backup |
| cyber_audit_reader | No | No | Targeted sensitive-table audit access |

Both cyberuser and cyber_backup were verified as non-superuser roles.

Neither application nor backup role has permission to create databases or roles, perform replication, or bypass row-level security.

The cyber_audit_reader role is a NOLOGIN role.

## 4. PostgreSQL Audit Logging

The following configuration was verified:

- shared_preload_libraries = pgaudit
- pgaudit.log = write, ddl, role
- pgaudit.role = cyber_audit_reader
- pgaudit.log_parameter = off
- log_connections = on
- log_disconnections = on

Audit logs confirmed that PostgreSQL recorded:

- Database role and privilege changes.
- DDL operations.
- Sensitive-table SELECT operations.
- Database restoration cleanup operations.

Sensitive tables tested:

- users
- login_attempts
- revoked_tokens
- security_response_audit
- security_response_audit_backup

Reads from all five tables were successfully recorded in PostgreSQL audit logs.

**Scope limitation:** Reads from other database tables are not globally audited by the current configuration.

## 5. Secure Automated Backup

A dedicated backup role named cyber_backup was configured.

The backup process uses:

- PostgreSQL pg_dump.
- Custom-format backup archives.
- A dedicated systemd oneshot service.
- A daily systemd timer.
- A 14-day retention rule.
- A password file protected by filesystem permissions.

Backup script:

/usr/local/sbin/backup-cyber-digital-twin.sh

Backup directory:

/var/backups/postgresql

Backup schedule:

Daily at 02:00 IST.

The systemd timer was verified as enabled and active.

Successful backup execution was confirmed through systemd journal logs.

## 6. Backup File Access Protection

Filesystem permissions were verified:

| Resource | Permission | Owner |
|---|---|---|
| Backup directory | 700 | postgres:postgres |
| Backup archives | 600 | postgres:postgres |
| SHA256SUMS | 600 | postgres:postgres |
| Backup script | 700 | postgres:postgres |
| .pgpass | 600 | postgres:postgres |

These permissions restrict access to the PostgreSQL service account.

## 7. Backup Integrity Verification

The following integrity checks were completed:

- PostgreSQL custom-format archive listing: PASSED
- SHA-256 checksum generation: PASSED
- Repeated checksum comparison: PASSED
- SHA256SUMS manifest creation: PASSED
- Manifest verification using sha256sum -c: PASSED

Verified backup:

cyber_digital_twin_20261107_155216.dump

SHA-256:

89e55ce52dc94080d9213ea1ceec6cf42752e782243254bbaea2d63b2fd77ff7

Verification result:

OK

**Limitation:** The checksum manifest is stored alongside the backup. It helps detect accidental corruption, but does not independently protect against an attacker who can modify both the archive and its manifest.

## 8. Database Restoration Testing

A temporary database named cyber_restore_test was created.

The verified backup was restored into this temporary database.

Results:

| Restoration Test | Result |
|---|---|
| Restore command | PASSED |
| Restored tables | 9 |
| Total restored rows | 15,635 |
| Indexes verified | 18 |
| Constraints verified | 35 |
| pgaudit extension | Restored |
| plpgsql extension | Restored |
| Production database modified | No |
| Temporary database cleanup | PASSED |

All nine restored table row counts matched the corresponding production database counts during verification.

The temporary restoration database was dropped after testing.

## 9. Findings and Recommendations

### Implemented Controls

1. Application and backup accounts use non-superuser database roles.
2. Sensitive database operations are recorded through pgaudit.
3. Sensitive-table reads are audited through a dedicated audit role.
4. Automated database backups are scheduled daily.
5. Backup files and credentials have restrictive filesystem permissions.
6. Backup archive integrity was verified using SHA-256.
7. Database restoration was successfully tested.

### Recommendations

1. Consider storing signed checksum manifests separately from backup archives.
2. Maintain an encrypted off-host backup copy.
3. Consider global READ auditing if the additional log volume and data exposure risks are acceptable.
4. Review backup-role SELECT privileges whenever new database tables are introduced.
5. Monitor backup service failures and periodically perform restoration tests.
6. Remove temporary test artifacts that are no longer required.

## 10. Final Audit Conclusion

The PostgreSQL database security audit was completed successfully.

The implemented controls provide database access restriction, targeted audit logging, automated backup protection, backup integrity verification, and tested restoration capability.

The restoration test demonstrated that the verified backup could recreate the database structure and data in a separate test database without modifying the production database.

Some improvements remain recommended, particularly independent checksum protection, encrypted off-host backups, and review of broader read-auditing coverage.

**Overall Result: Database Security Audit Completed.**
