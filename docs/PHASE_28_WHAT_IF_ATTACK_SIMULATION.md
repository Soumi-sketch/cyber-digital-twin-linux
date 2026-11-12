# Phase 28 - What-if Attack Simulation

## 1. Overview
Implemented a defensive, hypothetical attack simulation engine for the
AI-Powered Cyber Digital Twin for Linux Infrastructure.

The engine calculates potential security risk, impact, severity and
recommended controls without executing real attacks or changing the
monitored infrastructure.

## 2. Supported Scenarios
1. SSH Brute Force
2. Privilege Escalation
3. File Tampering
4. Suspicious Process
5. Network Exposure
6. Data Exfiltration

## 3. Safety Architecture
- Simulation mode is DRY-RUN only.
- No attack commands are executed.
- No SSH commands are sent to monitored servers.
- No firewall or service configuration is modified.
- No files are changed on monitored servers.
- Simulations do not create real security incidents.
- Results are stored for historical analysis.

## 4. Backend
Implementation:
- backend/simulation/attack_simulator.py
- backend/simulation/__init__.py
- backend/migrations/phase28_attack_simulations.sql

Database table: attack_simulations

Stored information:
- Scenario type
- Target hostname label
- Simulation parameters
- Simulation result
- Risk score
- Severity
- Simulation mode
- Executing user
- Creation timestamp

## 5. API Endpoints

| Method | Endpoint | Permission |
|---|---|---|
| GET | /simulation/scenarios | Admin, Analyst, Viewer |
| POST | /simulation/run | Admin, Analyst |
| GET | /simulation/history | Admin, Analyst, Viewer |
| GET | /simulation/history/{simulation_id} | Admin, Analyst, Viewer |

## 6. Role-Based Access Control

| Feature | Admin | Analyst | Viewer |
|---|---|---|---|
| View scenarios | Yes | Yes | Yes |
| Run simulations | Yes | Yes | No |
| View history | Yes | Yes | Yes |
| View simulation details | Yes | Yes | Yes |

Backend authorization is enforced through role dependencies.
The frontend also disables the Run action for Viewer accounts.

## 7. Verification

- Python compilation: PASS
- JavaScript syntax validation: PASS
- Git diff validation: PASS
- Six simulation scenarios tested.
- Admin API tests: PASS
- Analyst API tests: PASS
- Viewer API tests: PASS
- Viewer simulation execution correctly returns HTTP 403.
- All eight recorded simulations use DRY-RUN mode.
- Unsafe simulation records: 0.
- Dashboard role permissions visually verified.

## 8. Result
Phase 28 implements a safe what-if simulation dashboard with six
defensive scenarios, persistent simulation history, risk assessment,
recommended controls and role-based permissions.
