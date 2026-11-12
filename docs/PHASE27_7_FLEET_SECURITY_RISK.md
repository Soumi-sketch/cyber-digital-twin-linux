# Phase 27.7 - Fleet-Wide Security Risk

## Objective
Aggregate security risk across enabled monitored Linux hosts and
present a fleet-level risk score, severity distribution and per-host
risk breakdown.

## Implementation
- Backend: backend/security/fleet_risk_engine.py
- API: GET /fleet/security-risk
- Frontend: Fleet-Wide Security Risk panel
- Access: Admin, Analyst and Viewer

## Risk inputs
- SSH event risk
- Attack volume
- Cross-server campaign severity
- SSH incident severity

## Configured weights
| Component | Weight |
|---|---:|
| Event risk | 50% |
| Attack volume | 20% |
| Campaign severity | 20% |
| Incident severity | 10% |

## Severity scores
| Severity | Score |
|---|---:|
| LOW | 25 |
| MEDIUM | 50 |
| HIGH | 75 |
| CRITICAL | 100 |

The engine calculates host-level risk from the configured weighted
components and aggregates enabled-host risk into a fleet score.

## Dashboard
- Fleet risk score and level
- Severity distribution
- Recent incidents
- Active campaigns
- Per-server risk and attack statistics

## Verification
- Fleet security risk API returned HTTP 200.
- Admin, Analyst and Viewer read access verified.
- Dashboard displayed two enabled hosts.
- At the verification time, both hosts were LOW risk with a
  fleet score of 0.00.

## Interpretation and limitations
The risk score uses its configured recent-risk calculation window.
Historical SSH alerts can exist while the current fleet risk score
remains LOW. These values represent different views of security data.

The score is an analytical indicator, not proof that a host is
compromised or completely secure.
