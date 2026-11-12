
# Phase 27.6 – Cross-Server Security Event Correlation

## Objective

Detect coordinated SSH attacks in which the same source IP
targets multiple monitored Linux servers within a 30-minute
rolling time window.

## Architecture

- PostgreSQL `ssh_events` stores SSH security events.
- `cross_server_correlation.py` retrieves and correlates events.
- FastAPI exposes the detection results.
- The frontend displays cross-server campaigns.
- Existing single-server incident and campaign detection
  remains unchanged.

## Detection Criteria

- Event types: FAILED_LOGIN and INVALID_USER.
- Minimum attempts: 3.
- Minimum distinct target servers: 2.
- Correlation window: 30 minutes.
- Successful login events are excluded.

## Severity Rules

| Condition | Severity |
|---|---|
| 3–9 attempts and fewer than 3 hosts | MEDIUM |
| 10–19 attempts or 3 hosts | HIGH |
| 20+ attempts or 4+ hosts | CRITICAL |

## API

GET `/security/cross-server-campaigns`

Authentication is required.

Admin, Analyst and Viewer roles have read access.

## Dashboard

The Cross-Server Attack Campaigns section displays:

- Campaign ID
- Source IP
- Affected servers
- Server count
- Severity
- Total attempts
- Failed logins
- Invalid users
- Start and end times

The dashboard refreshes campaign data every 5 seconds.

## Validation

- Synthetic cross-server detection test passed.
- Single-server activity exclusion passed.
- Different-source separation passed.
- Old-event exclusion passed.
- Rolling-window boundary tests passed.
- Overlapping-window containment test passed.
- API authentication and RBAC tests passed.
- Existing campaign API regression test passed.
- Python compilation passed.
- JavaScript syntax check passed.
- Git whitespace validation passed.

## Production Data

The current production database returned zero qualifying
cross-server campaigns during the queried 30-minute window.
This is a valid empty result, not a detection failure.

## Limitations

The detector currently correlates SSH authentication
failures and invalid-user events. It does not yet correlate
other security telemetry such as process, network, or file
integrity events.

## Completion Checklist

- [x] Cross-server detection engine
- [x] Rolling time-window correlation
- [x] Campaign severity classification
- [x] Authenticated API endpoint
- [x] RBAC read access
- [x] Dashboard integration
- [x] Five-second refresh
- [x] Synthetic and regression tests
- [ ] Final verification
- [ ] Git commit and push
- [ ] VMware snapshot
