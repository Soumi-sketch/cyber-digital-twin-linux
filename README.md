# AI Powered Cyber Digital Twin for Linux

An AI-powered Cyber Digital Twin platform for near real-time Linux system monitoring, historical performance analysis, anomaly detection, and SSH security event monitoring.

---

## 📌 Overview

The **AI Powered Cyber Digital Twin** is a cybersecurity and system-monitoring platform designed to create a software-based representation of a Linux system.

The system continuously collects information from a remote Linux/RHEL machine, stores the collected data in PostgreSQL, provides REST APIs through FastAPI, performs AI-based anomaly analysis, and presents the results through a web dashboard.

The platform combines:

- Linux system monitoring
- Historical performance analysis
- AI-based anomaly detection
- SSH security event monitoring
- PostgreSQL data storage
- REST API services
- Web-based visualization

---

## 🎯 Problem Statement

Traditional monitoring systems mainly display current CPU, memory, and disk usage.

They may not provide a centralized view of:

- System health
- Historical behavior
- Resource anomalies
- SSH authentication activity
- Security-related events

This project addresses these limitations by creating a centralized Cyber Digital Twin for Linux systems.

---

## 🎯 Objectives

The main objectives are:

- Create a software-based representation of a Linux system.
- Monitor CPU, memory, and disk utilization.
- Collect system information remotely.
- Store historical monitoring data.
- Detect abnormal resource behavior.
- Monitor SSH authentication events.
- Provide REST APIs.
- Display system information through a dashboard.
- Automatically refresh monitoring information.

---

# ⭐ Key Features

## 1. Remote Linux Monitoring

The system collects:

- Hostname
- IP address
- Operating system
- Kernel version
- CPU usage
- Memory usage
- Disk usage
- System uptime

The implementation has been tested with RHEL Linux.

---

## 2. Real-Time System Health

The dashboard displays the current health of the monitored system.

| Condition | Status |
|---|---|
| Resources below 70% | Healthy |
| Any resource above 70% | Warning |
| Any resource above 90% | Critical |

---

## 3. Historical Monitoring

System metrics are stored in PostgreSQL.

The dashboard provides historical graphs for:

- CPU usage
- Memory usage
- Disk usage

The dashboard automatically refreshes the data every 5 seconds.

---

## 4. AI Anomaly Detection

The project includes an anomaly detection service.

It analyzes:

- CPU behavior
- Memory behavior
- Disk behavior

The dashboard displays:

- Normal
- Warning
- Anomaly

This provides an additional analysis layer beyond fixed threshold monitoring.

---

## 5. SSH Security Monitoring

The system monitors SSH authentication logs using Linux `journalctl`.

It detects:

- Successful SSH login
- Failed SSH login
- Invalid user attempts

Each event can contain:

- Event type
- Username
- Source IP
- Original SSH log message
- Event timestamp

Duplicate journal entries are prevented from being stored repeatedly.

---

## 6. PostgreSQL Database

The project uses PostgreSQL for persistent storage.

### `system_metrics`

Stores:

- Hostname
- IP address
- Operating system
- Kernel version
- CPU usage
- Memory usage
- Disk usage
- Uptime
- Collection timestamp

### `ssh_events`

Stores:

- Event ID
- Event type
- Username
- Source IP
- SSH message
- Event timestamp

---

# 🏗️ System Architecture

```text
                 Remote RHEL Linux System
                 ┌───────────────────────┐
                 │ CPU                   │
                 │ Memory                │
                 │ Disk                  │
                 │ System Information    │
                 │ SSH Logs              │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │      Collectors       │
                 │                       │
                 │ Remote Collector      │
                 │ SSH Collector         │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │      PostgreSQL       │
                 │                       │
                 │ system_metrics        │
                 │ ssh_events            │
                 └───────────┬───────────┘
                             │
                             ▼
                 ┌───────────────────────┐
                 │       FastAPI         │
                 │       Backend         │
                 │                       │
                 │ /health               │
                 │ /metrics              │
                 │ /metrics/history      │
                 │ /anomalies            │
                 │ /hosts                │
                 │ /ssh/events           │
                 └───────────┬───────────┘
                             │
                  ┌──────────┴──────────┐
                  │                     │
                  ▼                     ▼
          ┌───────────────┐     ┌────────────────┐
          │ AI Anomaly    │     │ Web Dashboard  │
          │ Detection     │     │                │
          │               │     │ Health         │
          │ CPU           │     │ Charts         │
          │ Memory        │     │ AI Status      │
          │ Disk          │     │ SSH Events     │
          └───────────────┘     └────────────────┘
```

## 🛠️ Technology Stack
| Component            | Technology                     |
| -------------------- | ------------------------------ |
| Operating System     | RHEL Linux                     |
| Programming Language | Python                         |
| Backend              | FastAPI                        |
| Database             | PostgreSQL                     |
| Database Access      | SQLAlchemy                     |
| System Monitoring    | psutil                         |
| Remote Communication | SSH / Paramiko                 |
| Log Monitoring       | journalctl / systemd           |
| AI Analysis          | Python-based anomaly detection |
| Frontend             | HTML, CSS, JavaScript          |
| Visualization        | Chart.js                       |
| Virtualization       | VMware                         |
| Version Control      | Git                            |
| Repository           | GitHub                         |

## 📁 Project Structure

```text
cyber-digital-twin/
├── backend/
│   ├── api/
│   │   └── main.py
│   ├── ai/
│   │   └── anomaly_service.py
│   ├── collector/
│   │   ├── remote_collector.py
│   │   └── ssh_collector.py
│   ├── scheduler/
│   │   └── collector_runner.py
│   └── database.py
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── .gitignore
├── README.md
└── requirements.txt
```

## 🔄 How the System Works

The complete workflow is:

```text
Remote RHEL VM
      ↓
Collect CPU / Memory / Disk
      ↓
Collect SSH Security Logs
      ↓
Collectors
      ↓
PostgreSQL Database
      ↓
FastAPI REST API
      ↓
AI Anomaly Detection
      ↓
Web Dashboard
```

The collector runs continuously and collects updated information every 5 seconds.

The dashboard also refreshes the displayed information every 5 seconds.

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/Soumi-sketch/cyber-digital-twin-linux.git
cd cyber-digital-twin-linux
```

### Create Virtual Environment

```bash
python3 -m venv venv
```

### Activate Virtual Environment

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure PostgreSQL

Create the PostgreSQL database and configure the database connection used by the project.

## ▶️ Running the Project

The project uses three terminals.

```bash
source venv/bin/activate
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
```
Terminal 2 — Collector

```bash
source venv/bin/activate
python -m backend.scheduler.collector_runner
```
Terminal 3 — Frontend

```bash
cd frontend
python3 -m http.server 5500 --bind 0.0.0.0
```
Open the dashboard:
http://SERVER-IP:5500

## 🔌 API Endpoints


| Endpoint           | Purpose               |
| ------------------ | --------------------- |
| `/`                | API welcome message   |
| `/health`          | Current system health |
| `/metrics`         | All system metrics    |
| `/metrics/history` | Historical metrics    |
| `/anomalies`       | AI anomaly analysis   |
| `/hosts`           | Monitored hosts       |
| `/ssh/events`      | SSH security events   |



Health API Example

```bash
curl http://127.0.0.1:8000/health
```

SSH Event API Example

```bash
curl "http://127.0.0.1:8000/ssh/events"
```

## 🧪 Testing and Verification

The project has been tested using RHEL Linux virtual machines.

### System Monitoring

Verified:

- CPU monitoring
- Memory monitoring
- Disk monitoring
- Hostname
- IP address
- System health
- Historical graphs

### AI Anomaly Detection

The dashboard was tested with changing system resource usage to verify anomaly status changes.

### SSH Monitoring

SSH authentication tests were performed using successful and failed login attempts.

Example event types:

- `SUCCESSFUL_LOGIN`
- `FAILED_LOGIN`

### Database Verification

```sql
SELECT id, event_type, username, source_ip, event_time
FROM ssh_events
ORDER BY id DESC
LIMIT 10;
```

The system successfully detected SSH authentication events and prevented duplicate journal entries.


## 🖥️ Dashboard

The dashboard provides a centralized view of the monitored Linux system.

It displays:

- Hostname
- System status
- CPU usage
- Memory usage
- Disk usage
- AI anomaly status
- CPU history
- Memory history
- Disk history
- SSH security events
- Failed login count
- Successful login count

The dashboard automatically refreshes every 5 seconds.

## 🔐 Security Monitoring

The SSH monitoring component provides visibility into Linux authentication activity.

It detects:

- Successful authentication
- Failed authentication
- Invalid users

The system records the username and source IP address associated with the event.

This can help administrators identify suspicious authentication activity.

## 🔮 Future Enhancements

Future versions can include:

- Multi-host monitoring
- Security alerts
- Email notifications
- Telegram notifications
- Advanced machine-learning models
- Attack-pattern detection
- User authentication
- Role-based access control
- HTTPS
- Docker deployment
- Cloud deployment
- Security event correlation
- Predictive system failure analysis

## 📸 Screenshots

Screenshots of the dashboard, API responses, system monitoring, and SSH security events can be added here.

Recommended screenshots:

- Dashboard screenshot
- API response screenshot
- SSH security event screenshot
- AI anomaly detection screenshot

## 📊 Project Testing Summary

| Feature                    | Status   |
| -------------------------- | -------- |
| Remote Linux Monitoring    | ✅ Tested |
| CPU Monitoring             | ✅ Tested |
| Memory Monitoring          | ✅ Tested |
| Disk Monitoring            | ✅ Tested |
| Historical Monitoring      | ✅ Tested |
| AI Anomaly Detection       | ✅ Tested |
| SSH Login Detection        | ✅ Tested |
| Failed Login Detection     | ✅ Tested |
| Successful Login Detection | ✅ Tested |
| PostgreSQL Storage         | ✅ Tested |
| FastAPI APIs               | ✅ Tested |
| Web Dashboard              | ✅ Tested |
| Automatic 5-second Refresh | ✅ Tested |


## ✅ Conclusion

The AI Powered Cyber Digital Twin for Linux provides an integrated platform for Linux system monitoring and cybersecurity visibility.

The project combines:

- Remote Linux monitoring
- PostgreSQL storage
- FastAPI REST APIs
- AI-based anomaly detection
- Historical performance analysis
- SSH security event monitoring
- Web-based visualization

The project demonstrates how a software-based digital representation of a Linux system can be used to monitor system health, identify abnormal behavior, and provide visibility into SSH authentication activity.
