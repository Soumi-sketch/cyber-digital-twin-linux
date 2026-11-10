
# Phase 22 – Advanced AI Threat Intelligence

**Project:** AI-Powered Cyber Digital Twin for Linux Infrastructure
**Phase:** 22
**Status:** Final validation in progress
**Platform:** RHEL 10, Python 3.12, FastAPI, PostgreSQL 16

---

## 1. Objective

The objective of Phase 22 is to integrate threat intelligence into the Cyber Digital Twin to identify malicious IP addresses, enrich SSH security events, correlate threat indicators with security events, and improve risk scoring.

## 2. Architecture

The threat intelligence workflow is:

1. Threat feeds provide known malicious indicators.
2. The feed manager validates and imports indicators.
3. PostgreSQL stores the indicators.
4. The IP reputation engine checks source IP addresses.
5. SSH events are enriched with threat intelligence.
6. The risk engine applies threat-based risk bonuses.
7. FastAPI provides authenticated threat intelligence endpoints.
8. The dashboard displays IOC statistics and malicious SSH matches.

## 3. Implemented Modules

| Module | Responsibility |
|---|---|
| threat_intelligence.py | IOC database model |
| feed_manager.py | Feed download, validation and import |
| ip_reputation.py | IP reputation checking |
| threat_enrichment.py | SSH event enrichment |
| risk_engine.py | Threat-based risk scoring |
| main.py | Threat intelligence REST APIs |
| app.js | Dashboard data loading |
| index.html | Threat intelligence dashboard |

## 4. IOC Database

Table: `threat_indicators`

Important fields:

- id
- indicator_type
- indicator_value
- threat_type
- severity
- confidence
- source
- description
- first_seen
- last_seen
- expires_at
- is_active
- created_at
- updated_at

A unique constraint prevents duplicate indicators from the same source.

## 5. Threat Feed Integration

Implemented feed:

**FEODO_TRACKER**

Feed URL:

https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt

The feed manager includes:

- Allowlisted feed sources
- HTTP timeout handling
- Streaming download
- 2 MB download limit
- Public IP validation
- Invalid indicator filtering
- Duplicate removal
- Dry-run import
- PostgreSQL upsert
- Database error handling

The feed currently assigns HIGH severity and 90 confidence to imported indicators.

## 6. IOC Expiry Management

Imported feed indicators receive a 24-hour expiry.

A successful subsequent import refreshes:

- last_seen
- expires_at
- updated_at

Expired indicators are excluded from active reputation checks.

A later successful feed update can reactivate and refresh an existing indicator.

## 7. IP Reputation Engine

The reputation engine supports:

- MALICIOUS
- UNKNOWN
- INVALID
- INACTIVE_OR_EXPIRED

It checks IP format and queries active, unexpired IP indicators.

## 8. SSH Event Enrichment

SSH events are enriched using source IP reputation.

Enrichment includes:

- Malicious status
- Threat type
- Severity
- Confidence
- Intelligence source

## 9. Threat-Based Risk Scoring

Threat bonuses:

| Threat severity | Bonus |
|---|---:|
| LOW | 10 |
| MEDIUM | 20 |
| HIGH | 30 |
| CRITICAL | 40 |

The bonus applies only when the IP is malicious and confidence is at least 50.

The total risk score is capped at 100.

Existing brute-force detection and base risk scoring remain integrated.

## 10. API Endpoints

| Method | Endpoint | Permission |
|---|---|---|
| GET | /threat-intelligence/check | All roles |
| POST | /threat-intelligence/feeds/{source_name}/sync | Admin |
| POST | /threat-intelligence/indicators | Admin |
| GET | /threat-intelligence/indicators | All roles |
| PATCH | /threat-intelligence/indicators/{indicator_id}/status | Admin |
| GET | /threat-intelligence/reputation/ip | All roles |

## 11. Role-Based Access Control

| Operation | Admin | Analyst | Viewer |
|---|---|---|---|
| Read threat intelligence | Yes | Yes | Yes |
| Check IP reputation | Yes | Yes | Yes |
| Synchronize threat feeds | Yes | No | No |
| Create indicators | Yes | No | No |
| Change indicator status | Yes | No | No |

## 12. Dashboard

Dashboard URL:

https://192.168.38.146

The Threat Intelligence Dashboard displays:

- Total indicators
- Active indicators
- Inactive indicators
- Malicious SSH matches
- IOC severity distribution
- Recent malicious SSH matches

## 13. Validation Results

| Test | Result |
|---|---|
| Python syntax validation | PASS |
| Feed allowlist validation | PASS |
| Empty feed rejection | PASS |
| 2 MB size limit | PASS |
| Network timeout handling | PASS |
| Database failure handling | PASS |
| Invalid IP validation | PASS |
| Duplicate IOC prevention | PASS |
| IOC expiry validation | PASS |
| IOC restoration | PASS |
| SSH threat enrichment | PASS |
| Threat-based risk scoring | PASS |
| Risk score maximum limit | PASS |
| API route registration | PASS |
| Admin feed synchronization | PASS |
| Analyst feed synchronization denial | PASS |
| Viewer feed synchronization denial | PASS |
| Read-only access for all roles | PASS |
| Dashboard validation | PASS |

## 14. Test Data

A synthetic IOC was used:

- IP: 198.51.100.25
- Source: PHASE22_TEST

A feed-imported IOC was also validated:

- IP: 50.16.16.211
- Source: FEODO_TRACKER
- Threat type: BOTNET_C2
- Severity: HIGH
- Confidence: 90

These are validation records, not evidence of an actual attack against the monitored infrastructure.

## 15. Security Considerations

- Feed sources are allowlisted.
- Download size and timeouts are restricted.
- IOC values are validated.
- Duplicate indicators are prevented by a database constraint.
- Feed synchronization is restricted to Admin.
- Feed imports support dry-run mode.
- Database operations use parameterized SQL.
- IOC expiry limits the lifetime of stale feed records.

## 16. Limitations

- One external feed source is currently configured.
- Threat intelligence depends on external feed availability.
- Existing SSH events may not match imported indicators.
- The configured severity and confidence are source-level defaults, not independently verified scores.
- A 24-hour expiry requires successful feed refreshes to maintain current indicators.
- Zero malicious SSH matches does not prove that the infrastructure is attack-free.

## 17. Conclusion

Phase 22 integrates threat intelligence into the Linux Cyber Digital Twin. The implementation connects IOC storage, feed management, IP reputation, SSH enrichment, risk scoring, API authorization and dashboard monitoring.

The validation tests demonstrate that the implemented components work together under the tested conditions.
