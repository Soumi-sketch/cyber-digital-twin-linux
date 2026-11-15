# AI-Powered Cyber Digital Twin for Linux Infrastructure

### Intelligent Infrastructure Monitoring · AI-Driven Analytics · Cybersecurity Visibility · Multi-Server Security Management

<p align="center">

**A centralized Cyber Digital Twin platform for monitoring, analyzing, and securing Linux infrastructure.**

</p>

---

## Project Overview

The **AI-Powered Cyber Digital Twin for Linux Infrastructure** is an integrated infrastructure monitoring and cybersecurity platform designed to create a centralized software-based representation of multiple Linux systems.

The platform continuously collects system metrics and security events from remote Linux hosts using SSH, processes the collected information through Python-based monitoring and security engines, stores persistent records in PostgreSQL, and exposes the results through FastAPI REST services and an interactive web dashboard.

It combines infrastructure monitoring, anomaly detection, predictive analytics, SSH threat detection, file integrity monitoring, process and service security, network monitoring, threat intelligence, security incident management, and role-based access control in one application.

The project has been developed and tested in a VMware-based Red Hat Enterprise Linux environment.

---

## Table of Contents

1. [Project Highlights](#-project-highlights)
2. [Problem Statement](#-problem-statement)
3. [Objectives](#-project-objectives)
4. [System Architecture](#-system-architecture)
5. [Technology Stack](#-technology-stack)
6. [Core Features](#-core-features)
7. [Security and Access Control](#-security-and-access-control)
8. [System Workflow](#-system-workflow)
9. [Lab Environment](#-lab-environment)
10. [Project Structure](#-project-structure)
11. [Installation and Configuration](#-installation-and-configuration)
12. [Running the Application](#-running-the-application)
13. [API Documentation](#-api-documentation)
14. [Database Architecture](#-database-architecture)
15. [Testing and Validation](#-testing-and-validation)
16. [Security Considerations](#-security-considerations)
17. [Deployment Architecture and Roadmap](#-deployment-architecture-and-roadmap)
18. [Known Limitations](#-known-limitations)
19. [Future Enhancements](#-future-enhancements)
20. [Project Documentation](#-project-documentation)
21. [Author](#-author)

---

# 1. Project Highlights

| Capability | Description |
|---|---|
| Multi-Server Monitoring | Centralized monitoring of multiple Linux hosts |
| Remote Collection | SSH-based communication using Paramiko |
| Infrastructure Health | API, database, collector and host health monitoring |
| Historical Analytics | Persistent metrics and historical visualization |
| AI/ML Analysis | Anomaly detection and predictive analysis |
| SSH Threat Detection | Authentication-event monitoring and risk scoring |
| Threat Intelligence | Indicators, IP reputation and threat enrichment |
| File Integrity Monitoring | Baselines and file-change detection |
| Process Security | Suspicious process and service monitoring |
| Network Security | Interfaces, connections, listeners and alerts |
| Incident Management | Assignment, acknowledgement, investigation and resolution |
| Fleet Security | Cross-server risk and alert aggregation |
| Notifications | Email, Telegram and dashboard notification channels |
| RBAC | Admin, Analyst and Viewer authorization |
| Attack Simulation | Six hypothetical security scenarios |
| Response Workflows | Controlled response recommendations and audit records |

---

# 2. Problem Statement

Modern Linux infrastructures require more than basic resource monitoring.

Administrators and security teams need to understand both the operational condition and security posture of their systems.

Traditional monitoring approaches may require separate tools for:

- CPU, memory and disk monitoring.
- Historical performance analysis.
- SSH authentication monitoring.
- Suspicious process detection.
- File integrity verification.
- Network activity monitoring.
- Threat intelligence.
- Security incident investigation.
- Multi-server visibility.
- Security response auditing.

Managing these functions independently can make it difficult to correlate system behavior and security activity across multiple servers.

This project addresses that challenge by developing a centralized Cyber Digital Twin that combines infrastructure monitoring and cybersecurity analytics in a unified platform.

---

# 3. Project Objectives

The main objectives are:

1. Develop a centralized monitoring platform for Linux infrastructure.
2. Establish secure remote communication with monitored hosts through SSH.
3. Collect system metrics and security events continuously.
4. Store monitoring and security records in PostgreSQL.
5. Develop REST APIs using FastAPI.
6. Implement system anomaly detection and predictive analysis.
7. Detect suspicious SSH authentication patterns.
8. Implement security risk scoring and alert generation.
9. Integrate threat intelligence and IP reputation analysis.
10. Monitor file integrity, processes, services and network activity.
11. Implement centralized incident management.
12. Provide cross-server security correlation and fleet risk analysis.
13. Implement authenticated access and role-based authorization.
14. Provide controlled security simulation and response workflows.
15. Develop a centralized interactive security dashboard.

---

# 4. System Architecture

The platform follows a centralized controller architecture.

A controller communicates with remote Linux hosts through SSH, collects monitoring information, processes security events and stores data in PostgreSQL.

FastAPI exposes application functionality through REST endpoints, while the frontend presents the collected information through a centralized dashboard.

## High-Level Architecture

```text
                 CENTRAL CONTROLLER
              Red Hat Enterprise Linux
                         |
       +-----------------+-----------------+
       |                 |                 |
       v                 v                 v
   FastAPI API       PostgreSQL       Web Dashboard
       |                 ^                 |
       |                 |                 |
       +----------+------+-----------------+
                  |
                  v
          MONITORING COLLECTOR
             SSH / Paramiko
                  |
          +-------+-------+
          |               |
          v               v
      Linux Host 1    Linux Host 2
      prac-server       attacker
          |               |
     System Metrics  System Metrics
     SSH Events       SSH Events
     Processes        Processes
     Services         Services
     Network          Network
     File Integrity   File Integrity
          |               |
          +-------+-------+
                  |
                  v
          SECURITY PROCESSING
                  |
       +----------+-----------+
       |          |           |
       v          v           v
    AI/ML     Threat       Security
   Analytics Intelligence  Engines
       |          |           |
       +----------+-----------+
                  |
                  v
          Risk / Alerts / Incidents
                  |
                  v
           CENTRAL DASHBOARD
```

## Main Architectural Components

| Component | Responsibility |
|---|---|
| Remote Hosts | Provide system and security information |
| SSH Collector | Retrieves remote monitoring data and logs |
| System Collector | Collects Linux resource information |
| PostgreSQL | Stores monitoring and security records |
| FastAPI | Provides application APIs and authentication |
| AI/Analytics | Performs anomaly and predictive analysis |
| Security Engines | Evaluate threats, risks and incidents |
| Notification Services | Handle configured notification channels |
| Frontend | Displays infrastructure and security information |

---

# 5. Technology Stack

| Layer | Technologies |
|---|---|
| Operating System | Red Hat Enterprise Linux |
| Programming Language | Python |
| Backend Framework | FastAPI |
| API Server | Uvicorn |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Remote Communication | SSH, Paramiko |
| System Monitoring | psutil |
| Log Collection | journalctl, systemd |
| Data Processing | NumPy, Pandas |
| Machine Learning | scikit-learn |
| Authentication | JWT |
| Password Hashing | bcrypt |
| Configuration | python-dotenv |
| Frontend | HTML5, CSS3, JavaScript |
| Visualization | Chart.js |
| Virtualization | VMware |
| Version Control | Git |
| Repository Hosting | GitHub |

---

# 6. Core Features

## 6.1 Multi-Server Linux Infrastructure Monitoring

The platform supports centralized monitoring of multiple remote Linux hosts.

Collected information includes:

- Hostname.
- IP address.
- Operating system.
- Kernel version.
- CPU utilization.
- Memory utilization.
- Disk utilization.
- System uptime.
- Collection timestamps.
- Host availability and last-seen information.

Remote communication is implemented using SSH through Paramiko.

## 6.2 Infrastructure Health Monitoring

The platform evaluates the health of application infrastructure components.

Monitored components include:

- FastAPI availability.
- PostgreSQL connectivity.
- Collector health.
- Controller disk utilization.
- Monitored-host freshness.

Infrastructure component health and individual host resource status are evaluated separately.

## 6.3 Resource Monitoring and Historical Analytics

System metrics are stored in PostgreSQL for historical analysis.

The dashboard provides resource visualization for:

- CPU utilization.
- Memory utilization.
- Disk utilization.
- Historical resource behavior.
- Host-specific monitoring information.

Resource thresholds used by the current host status logic:

| Resource Condition | Classification |
|---|---|
| Resources below 70% | Healthy |
| Any resource above 70% | Warning |
| Any resource above 90% | Critical |

## 6.4 Automatic Dashboard Refresh

Dashboard sections refresh automatically using their configured intervals.

This allows the user to observe updated infrastructure and security information without manually reloading the page.

The refresh implementation uses managed JavaScript timers.

## 6.5 AI-Based Anomaly Detection

The project contains dedicated anomaly-analysis modules.

The system analyzes system resource behavior and provides anomaly information for:

- CPU utilization.
- Memory utilization.
- Disk utilization.

The dashboard presents analytical states such as Normal, Warning and Anomaly.

## 6.6 Machine Learning and Predictive Analytics

The AI and analytics components include:

- Machine-learning anomaly detection.
- Predictive failure analysis.
- Anomaly forecasting.
- Predictive security risk.
- Attack-pattern prediction.
- Predictive alerts.
- Security decision analysis.
- Incident confidence analysis.

These analytical outputs assist investigation and prioritization. They are not guarantees that a future event will occur.

## 6.7 SSH Security Monitoring

The SSH collector retrieves authentication events from remote Linux systems.

Monitored events include:

- Successful login.
- Failed login.
- Invalid user attempts.

Recorded event information can include:

- Event ID.
- Event type.
- Username.
- Source IP.
- Original log message.
- Event timestamp.
- Associated hostname.

## 6.8 SSH Risk Scoring and Attack Detection

The security engine analyzes SSH events and calculates risk based on suspicious authentication behavior.

Detection logic includes:

- Repeated failed login attempts.
- Invalid-user attempts.
- Suspicious root authentication activity.
- Repeated authentication patterns.
- Source-based risk analysis.
- Security alert generation.

Risk classifications include Medium, High and Critical.

## 6.9 Threat Intelligence and IP Reputation

The threat intelligence subsystem provides:

- Indicator management.
- Threat feed synchronization.
- IP reputation analysis.
- Threat enrichment.
- Indicator status management.
- Malicious-source matching.
- Security intelligence correlation.

## 6.10 File Integrity Monitoring

The File Integrity Monitoring subsystem provides:

- File integrity baselines.
- SHA-256-based integrity verification.
- Scheduled integrity scanning.
- File creation detection.
- File modification detection.
- File deletion detection.
- Integrity event history.

## 6.11 Process and Service Security Monitoring

The process and service monitoring subsystem collects and analyzes:

- Process inventory.
- Suspicious process activity.
- Service inventory.
- Service-state changes.
- Process detections.
- Service alerts.
- Historical monitoring records.

## 6.12 Network Security Monitoring

The network monitoring subsystem provides information about:

- Network interfaces.
- Listening ports.
- Active network connections.
- Network activity.
- Suspicious listeners.
- Network security alerts.

## 6.13 Security Incident Management

The incident-management subsystem supports:

- Incident creation.
- Severity classification.
- Incident assignment.
- Acknowledgement.
- Investigation notes.
- Status tracking.
- Incident resolution.
- Incident reopening.
- Escalation.
- Reminders.
- Incident history and audit records.

## 6.14 Multi-Server Fleet Management

The fleet subsystem provides centralized visibility across monitored hosts.

Features include:

- Host inventory.
- Host grouping.
- Host organization.
- Fleet overview.
- Host details.
- Resource comparison.
- Fleet security risk scoring.
- Fleet alert aggregation.
- Cross-server security correlation.

## 6.15 Notification Management

The notification subsystem supports:

- Email notifications.
- Telegram notifications.
- Dashboard notifications.
- Severity-based policies.
- Notification settings.
- Notification history.
- Delivery-health monitoring.
- Notification analytics.
- Notification policy simulation.

Notification delivery depends on valid external service configuration and connectivity.

## 6.16 What-if Attack Simulation

The simulation subsystem provides hypothetical security scenarios:

1. SSH brute force.
2. Privilege escalation.
3. File tampering.
4. Suspicious process.
5. Network exposure.
6. Data exfiltration.

The simulation engine evaluates scenarios without performing real attacks or executing destructive commands.

## 6.17 Advanced Incident Response

The response subsystem supports:

- Response recommendations.
- Response planning.
- Controlled workflow records.
- Execution audit history.
- DRY-RUN safeguards.

The tested response workflows use simulated execution records rather than destructive live containment.

---

# 7. Security and Access Control

The application uses JWT-based authentication and role-based authorization.

## Authentication

Security-related functionality includes:

- Password hashing using bcrypt.
- JWT token generation.
- Token validation.
- Token revocation.
- Protected API access.
- Role-based authorization.

## RBAC Roles

| Permission | Admin | Analyst | Viewer |
|---|:---:|:---:|:---:|
| View dashboard | Yes | Yes | Yes |
| View infrastructure | Yes | Yes | Yes |
| View security information | Yes | Yes | Yes |
| Manage administrative settings | Yes | No | No |
| Execute privileged response actions | Yes | No | No |
| Change incident status | Yes | No | No |
| Perform permitted security investigation | Yes | Yes | Read-only |

Actual permissions are enforced at the backend API level. Frontend visibility alone is not treated as an authorization boundary.

---

# 8. System Workflow

The platform follows this general processing workflow:

```text
1. Remote Linux Host
          |
          v
2. SSH Connection
          |
          v
3. Remote Data Collection
          |
          +-----------------------+
          |                       |
          v                       v
4. System Metrics          5. Security Events
          |                       |
          v                       v
6. PostgreSQL Storage      7. Security Analysis
          |                       |
          v                       v
8. FastAPI Services        9. Risk and Alerts
          |                       |
          +-----------+-----------+
                      |
                      v
              10. Web Dashboard
                      |
                      v
             Monitoring and Analysis
```

The continuous collector handles system and security collection, while scheduled security modules perform their respective scans.

---

# 9. Lab Environment

The project has been developed and tested in a VMware-based RHEL environment.

| Machine | Hostname | IP Address | Role |
|---|---|---|---|
| Controller | twin | 192.168.38.146 | Backend, PostgreSQL, collector and dashboard |
| Monitored Host 1 | prac-server | 192.168.38.145 | Monitored Linux host |
| Monitored Host 2 | attacker | 192.168.38.147 | Testing Linux host |

The current environment uses SSH to communicate with monitored hosts.

**Note:** These are development-lab addresses. They must be replaced with the addresses appropriate for another deployment environment.

---

# 10. Project Structure

```text
cyber-digital-twin/
|
+-- backend/
|   |
|   +-- ai/
|   |   +-- anomaly_detector.py
|   |   +-- anomaly_service.py
|   |   +-- incident_confidence.py
|   |   +-- ml_anomaly_detector.py
|   |   +-- predictive_failure.py
|   |   +-- security_decision_engine.py
|   |
|   +-- analytics/
|   |   +-- anomaly_forecast.py
|   |   +-- attack_pattern_predictor.py
|   |   +-- notification_analytics.py
|   |   +-- predictive_alerts.py
|   |   +-- predictive_risk.py
|   |   +-- security_history.py
|   |
|   +-- api/
|   |   +-- main.py
|   |   +-- routes.py
|   |
|   +-- auth/
|   |   +-- dependencies.py
|   |   +-- jwt_handler.py
|   |   +-- password.py
|   |   +-- routes.py
|   |
|   +-- collector/
|   |   +-- parser.py
|   |   +-- remote_collector.py
|   |   +-- ssh_collector.py
|   |   +-- system_collector.py
|   |
|   +-- config/
|   |   +-- hosts.py
|   |
|   +-- migrations/
|   |
|   +-- models/
|   |
|   +-- notifications/
|   |
|   +-- scheduler/
|   |   +-- collector_runner.py
|   |
|   +-- security/
|   |
|   +-- simulation/
|   |
|   +-- utils/
|   |
|   +-- database.py
|
+-- deployment/
|   +-- systemd/
|       +-- cyber-collector.service
|
+-- docs/
|   +-- Phase documentation
|   +-- Testing reports
|   +-- Security audit reports
|
+-- frontend/
|   +-- index.html
|   +-- app.js
|   +-- style.css
|
+-- backups/
|
+-- .gitignore
+-- README.md
+-- requirements.txt
```

The structure above is representative. The repository contains additional supporting modules, migrations and development files.

---

# 11. Installation and Configuration

## Prerequisites

- Red Hat Enterprise Linux or another compatible Linux distribution.
- Python 3.
- PostgreSQL.
- Git.
- SSH access to monitored Linux hosts.
- Network connectivity between the controller and monitored hosts.

## Step 1: Clone the Repository

```bash
git clone https://github.com/Soumi-sketch/cyber-digital-twin-linux.git

cd cyber-digital-twin-linux
```

## Step 2: Create a Virtual Environment

```bash
python3 -m venv venv

source venv/bin/activate
```

## Step 3: Install Dependencies

```bash
pip install --upgrade pip

pip install -r requirements.txt
```

## Step 4: Configure Environment Variables

Create a local `.env` file in the project root.

```ini
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cyber_digital_twin
DB_USER=your_database_user
DB_PASSWORD=your_database_password

USERNAME=your_monitored_host_username
PASSWORD=your_monitored_host_password

JWT_SECRET_KEY=replace_with_a_secure_random_secret
```

These are configuration placeholders, not working credentials.

The application reads database settings through `backend/database.py` and monitored-host settings through `backend/config/hosts.py`.

Update the monitored-host configuration to match your own infrastructure.

For production, use protected SSH keys and a dedicated least-privilege service account wherever practical.

## Step 5: Configure PostgreSQL

Create the application database and database user.

Configure the connection settings in `.env`.

The database connection is initialized through:

```text
backend/database.py
```

Apply the database migrations required by the application version being deployed.

## Step 6: Verify SSH Connectivity

Test remote access to each monitored host:

```bash
ssh username@MONITORED_HOST_IP
```

Ensure the collector has the necessary permissions to retrieve the configured system and security information.

---

# 12. Running the Application

## Start the Backend API

From the project root:

```bash
source venv/bin/activate

uvicorn backend.api.main:app \
    --host 0.0.0.0 \
    --port 8000
```

The API is available at:

```text
http://SERVER-IP:8000
```

## Start the Collector

Open another terminal:

```bash
cd ~/cyber-digital-twin

source venv/bin/activate

python -m backend.scheduler.collector_runner
```

The collector continuously processes configured remote hosts.

## Collector Service

The repository contains a systemd service definition:

```text
deployment/systemd/cyber-collector.service
```

It is configured to start the collector using the project's Python virtual environment, with automatic restart settings.

Review the service user, working directory, paths and permissions before installing it on another machine.

## Start the Frontend

Serve the frontend using the web-server configuration appropriate to the environment.

The frontend directory is:

```text
frontend/
```

The current VMware dashboard is accessed through:

```text
https://192.168.38.146
```

For a new deployment, configure the frontend API connection, web server and HTTPS certificate for the new environment.

---

# 13. API Documentation

The backend provides REST APIs for infrastructure monitoring, authentication, analytics, security operations, notifications and fleet management.

The following is a feature-oriented API reference, not an exhaustive listing of every route.

## Core Monitoring APIs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API welcome endpoint |
| GET | `/metrics` | System metrics |
| GET | `/metrics/history` | Historical metrics |
| GET | `/anomalies` | Anomaly analysis |
| GET | `/ml/anomalies` | ML anomaly analysis |
| GET | `/predictive/failure` | Predictive failure analysis |
| GET | `/hosts` | Monitored hosts |
| GET | `/health` | Application health |
| GET | `/infrastructure/health` | Infrastructure health |
| GET | `/ssh/events` | SSH events |

## Security APIs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/security/risk` | Security risk information |
| GET | `/security/alerts` | Security alerts |
| GET | `/security/campaigns` | Attack campaigns |
| GET | `/security/cross-server-campaigns` | Cross-server correlation |
| GET | `/security/incidents` | Security incidents |
| GET | `/security/responses` | Response records |
| GET | `/security/response-audit` | Response audit |
| GET | `/security/decisions` | Security decisions |

## Incident Management APIs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/security/incidents/{incident_id}/status` | Incident status |
| GET | `/security/incidents/{incident_id}/history` | Incident history |
| GET | `/security/incidents/{incident_id}/workflow` | Incident workflow |
| POST | `/security/incidents/{incident_id}/status` | Update incident status |
| POST | `/security/incidents/{incident_id}/assign` | Assign incident |
| POST | `/security/incidents/{incident_id}/acknowledge` | Acknowledge incident |
| POST | `/security/incidents/{incident_id}/notes` | Add investigation notes |
| POST | `/security/incidents/{incident_id}/resolve` | Resolve incident |
| POST | `/security/incidents/{incident_id}/reopen` | Reopen incident |

## Threat Intelligence APIs

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/threat-intelligence/indicators` | Add an indicator |
| GET | `/threat-intelligence/indicators` | List indicators |
| GET | `/threat-intelligence/check` | Check indicators |
| PATCH | `/threat-intelligence/indicators/{indicator_id}/status` | Update indicator status |
| GET | `/threat-intelligence/reputation/ip` | IP reputation |
| POST | `/threat-intelligence/feeds/{source_name}/sync` | Synchronize threat feeds |

## Analytics APIs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/security/analytics/history` | Security history |
| GET | `/security/analytics/attack-trends` | Attack trends |
| GET | `/security/analytics/predictive-risk` | Predictive risk |
| GET | `/security/analytics/anomaly-forecast` | Anomaly forecasting |
| GET | `/security/analytics/attack-patterns` | Attack-pattern analysis |
| GET | `/security/analytics/predictive-alerts` | Predictive alerts |

## Advanced Security APIs

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/security/fim/baseline/{hostname}` | Create FIM baseline |
| POST | `/security/fim/scan/{hostname}` | Run integrity scan |
| GET | `/security/fim/events` | FIM events |
| GET | `/security/fim/baselines` | FIM baselines |
| GET | `/security/process-services/summary` | Process/service summary |
| GET | `/security/process-services/detections` | Process detections |
| GET | `/security/process-services/service-changes` | Service changes |
| GET | `/security/process-services/alerts` | Process/service alerts |
| GET | `/security/network/summary` | Network summary |
| GET | `/security/network/interfaces` | Network interfaces |
| GET | `/security/network/listeners` | Listening ports |
| GET | `/security/network/connections` | Active connections |
| GET | `/security/network/alerts` | Network alerts |

## Fleet and Simulation APIs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/fleet/overview` | Fleet overview |
| GET | `/fleet/security-risk` | Fleet risk |
| GET | `/fleet/security-alerts` | Fleet alerts |
| GET | `/inventory/groups` | Host groups |
| GET | `/inventory/hosts` | Host inventory |
| GET | `/simulation/scenarios` | Simulation scenarios |
| POST | `/simulation/run` | Execute hypothetical simulation |
| GET | `/simulation/history` | Simulation history |

## Notification APIs

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/security/notification-settings` | Notification settings |
| PUT | `/security/notification-settings/{severity}/{channel}` | Update notification policy |
| GET | `/security/notification-settings/audit` | Settings audit |
| GET | `/security/notification-history` | Notification history |
| GET | `/security/delivery-health` | Delivery health |
| GET | `/security/notification-analytics` | Notification analytics |
| POST | `/security/notification-simulator` | Notification simulation |
| GET | `/security/notification-simulator/history` | Simulation history |

## Interactive API Documentation

When the backend is running, FastAPI's interactive documentation is available at:

```text
http://SERVER-IP:8000/docs
```

The OpenAPI specification can be accessed at:

```text
http://SERVER-IP:8000/openapi.json
```

Protected operations require valid authentication and the appropriate role.

---

# 14. Database Architecture

PostgreSQL is used for persistent storage of infrastructure metrics, authentication activity, security findings and application records.

Important database areas include:

| Data Area | Purpose |
|---|---|
| System Metrics | Historical resource monitoring |
| SSH Events | Authentication-event records |
| Monitored Hosts | Host inventory |
| Users | Application authentication |
| Revoked Tokens | Token revocation |
| Threat Indicators | Threat intelligence |
| FIM Baselines | File integrity reference data |
| FIM Events | File integrity changes |
| Process Inventory | Process monitoring |
| Service Inventory | Service monitoring |
| Network Connections | Network activity |
| Network Listeners | Listening-port information |
| Security Incidents | Incident management |
| Response Audit | Response workflow records |
| Notification Settings | Notification policies |
| Notification History | Notification records |
| Attack Simulations | Hypothetical simulation records |

The exact schema depends on the applied migrations and current application version.

### Database Verification Example

```sql
SELECT
    id,
    event_type,
    username,
    source_ip,
    event_time
FROM ssh_events
ORDER BY id DESC
LIMIT 10;
```

### Backup and Recovery

A historical database archive was successfully restored into an isolated test database.

However, the restored archive did not contain all tables present in the latest production database.

Complete recovery of the latest production database has therefore not yet been verified.

A production deployment should include regular automated backups, integrity checks, isolated restore testing and documented recovery procedures.

---

# 15. Testing and Validation

The project underwent functional, integration, security, API, performance and operational testing in the VMware RHEL lab.

## Phase 30 Testing Summary

| Validation Area | Recorded Result |
|---|---|
| Backend compilation | Passed |
| Frontend JavaScript syntax | Passed |
| Dependency validation | Passed |
| Git whitespace validation | Passed |
| Pytest suite | 4 passed |
| API route registration | 86 routes recorded |
| OpenAPI endpoint | HTTP 200 |
| Protected API authentication | HTTP 401 in tested cases |
| PostgreSQL connectivity | Verified |
| Continuous collector | Verified |
| Multi-host collection | Verified |
| SSH event collection | Verified |
| Process/service monitoring | Verified |
| Network monitoring | Verified |
| RBAC unit tests | 4 passed |
| Sequential API benchmark | 10/10 successful |
| Concurrent API benchmark | 50/50 successful |
| ML validation script | Exit code 0 |

## Additional Verification

### RBAC

The Admin, Analyst and Viewer roles were tested against protected operations.

The recorded RBAC verification reached 24/24 checks passed.

### Dashboard Refresh

The dashboard was verified to refresh without manual reload.

Different sections use their configured refresh intervals.

### Notification Delivery

The direct email and Telegram delivery functions returned successful delivery results during testing.

### Performance

A later bounded API test recorded:

| Metric | Result |
|---|---:|
| Requests | 100 |
| Successful HTTP responses | 100 |
| Concurrency | 5 |
| Requests per second | 263.84 |
| Average latency | 18.06 ms |
| Maximum latency | 177.96 ms |

These are observed VMware lab results, not production capacity guarantees.

### Machine Learning Validation

The manual ML validation script analyzed historical samples successfully and exited with code 0.

### Security Response Testing

Simulation and response workflows were tested with DRY-RUN safeguards. The tests did not perform destructive live containment.

## Testing Scope

The results above describe the recorded lab testing. They do not imply that production-scale stress testing, complete disaster recovery validation or cloud deployment has been completed.

---

# 16. Security Considerations

Security is a core design requirement of this project.

For deployment in another environment:

1. Never commit `.env` files or credentials.
2. Never publish private SSH keys or JWT secrets.
3. Use strong database passwords.
4. Use protected SSH key authentication where practical.
5. Apply least-privilege access to monitored hosts.
6. Restrict PostgreSQL network access.
7. Use HTTPS with a valid TLS certificate.
8. Enforce backend authentication and authorization.
9. Restrict access to administrative operations.
10. Protect application logs and backup archives.
11. Regularly update operating-system packages and dependencies.
12. Validate response workflows in an isolated environment before enabling real actions.

The project is intended as an infrastructure monitoring and cybersecurity visibility platform. It should not be treated as a replacement for a complete enterprise SIEM, EDR or incident-response platform.

---

# 17. Deployment Architecture and Roadmap

## Current Deployment: VMware Lab

The current implementation runs in a VMware-based RHEL environment.

The controller hosts the backend, database, collector and dashboard services, while remote Linux systems are monitored through SSH.

## Phase 31: Docker Deployment — Planned

The next milestone is containerization.

Planned components:

- Backend Dockerfile.
- Frontend container.
- PostgreSQL container configuration.
- Docker Compose orchestration.
- Environment-based configuration.
- Persistent database volumes.
- Container networking.
- Health checks.
- Container startup and recovery validation.

Docker deployment will be marked complete after implementation and testing.

## Phase 32: Cloud Deployment — Planned

The cloud milestone will focus on deploying the platform in a secure cloud environment.

Planned activities:

- Cloud Linux instance provisioning.
- Application deployment.
- Database configuration.
- Network security rules.
- Firewall configuration.
- HTTPS and TLS setup.
- Secure remote-host connectivity.
- Cloud monitoring.
- Backup and recovery validation.
- Deployment testing.

Cloud deployment will be marked complete only after the application is deployed and verified.

---

# 18. Known Limitations

The current implementation has several limitations that should be considered before production deployment.

- Testing has been performed primarily in a small VMware lab.
- Production-scale load testing has not been completed.
- Complete recovery of the latest production database has not been verified.
- Docker deployment is a planned milestone.
- Cloud deployment is a planned milestone.
- Predictive and anomaly-analysis results are analytical indicators, not guaranteed outcomes.
- Real destructive response operations have not been validated as part of the DRY-RUN testing.
- Deployment configuration, TLS certificates, SSH access and database credentials must be adapted to the target environment.

---

# 19. Future Enhancements

Potential improvements include:

- Containerized deployment.
- Cloud-native deployment.
- High availability and redundancy.
- Scalable remote collection.
- Enhanced machine-learning models.
- More advanced behavioral analytics.
- Additional threat intelligence integrations.
- Centralized logging integrations.
- Automated backup and disaster recovery.
- Expanded security testing.
- Production monitoring and alerting.
- Improved operational reporting.

---

# 20. Project Documentation

Technical documentation and phase reports are maintained in the `docs/` directory.

The available documentation covers:

- Database and security audits.
- Threat intelligence.
- Predictive security analytics.
- File integrity monitoring.
- Process and service security.
- Network security.
- Host inventory.
- Fleet monitoring.
- Cross-server security correlation.
- What-if attack simulation.
- Advanced incident response.
- Testing and performance optimization.

---

# 21. Repository

**GitHub Repository**

https://github.com/Soumi-sketch/cyber-digital-twin-linux

The repository contains the application source code, frontend, backend modules, deployment configuration and project documentation.

---

# 22. Author

**Soumi Dutta**

B.Sc. Advanced Networking and Cybersecurity (Honours)
Brainware University

**GitHub:** https://github.com/Soumi-sketch

---

# 23. Conclusion

The **AI-Powered Cyber Digital Twin for Linux Infrastructure** demonstrates the integration of Linux administration, infrastructure monitoring, cybersecurity analysis, machine learning and centralized security management.

The platform combines remote SSH-based monitoring, PostgreSQL persistence, FastAPI services, anomaly detection, predictive analytics, threat intelligence, file integrity monitoring, process and network security, incident management, fleet-level analysis and role-based access control.

The project provides a foundation for understanding infrastructure behavior, identifying suspicious activity and managing security information across multiple Linux hosts through a centralized dashboard.

The VMware implementation and Phase 30 testing establish the current verified development milestone. Docker and cloud deployment are the next planned stages toward a more portable and scalable architecture.

---

<p align="center">

**AI-Powered Cyber Digital Twin for Linux Infrastructure**

*Monitor. Analyze. Detect. Secure.*

**Developed by Soumi Dutta**

</p>
