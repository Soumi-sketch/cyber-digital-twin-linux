# AI Powered Cyber Digital Twin for Linux

An AI-powered Cyber Digital Twin platform for real-time Linux system monitoring, historical performance analysis, anomaly detection, and SSH security event monitoring.

## 📌 Overview

The **AI Powered Cyber Digital Twin** is a cybersecurity and system-monitoring platform designed to create a software-based representation of a Linux system.

The system continuously collects information from a remote Linux/RHEL machine, stores the collected data in PostgreSQL, exposes the information through a FastAPI backend, performs AI-based anomaly analysis, and presents the results through a web dashboard.

The platform combines:

- System resource monitoring
- Historical performance tracking
- AI-based anomaly detection
- SSH security event monitoring
- PostgreSQL data storage
- REST API services
- Real-time web visualization

---

## 🎯 Problem Statement

Traditional system monitoring tools mainly display current resource usage. They may not provide an integrated view of system health, historical behavior, abnormal resource usage, and SSH security events.

This project addresses this problem by creating a centralized Cyber Digital Twin that can:

1. Monitor remote Linux systems.
2. Collect CPU, memory, disk, and system information.
3. Store historical system metrics.
4. Detect abnormal resource behavior.
5. Monitor SSH authentication events.
6. Display security and system information through a dashboard.

---

## 🎯 Objectives

The main objectives of the project are:

- Develop a software-based digital representation of a Linux system.
- Monitor CPU, memory, and disk utilization.
- Collect system information remotely.
- Store monitoring data in PostgreSQL.
- Provide REST APIs using FastAPI.
- Perform AI-based anomaly detection.
- Detect failed and successful SSH logins.
- Display historical system behavior.
- Provide a centralized monitoring dashboard.
- Automatically refresh monitoring information.

---

# ⭐ Key Features

## 1. Remote Linux Monitoring

The system remotely collects:

- Hostname
- IP address
- Operating system
- Kernel version
- CPU usage
- Memory usage
- Disk usage
- System uptime

The current implementation has been tested with a RHEL Linux target system.

---

## 2. Real-Time System Health

The dashboard displays the latest system condition.

The health status is classified as:

| Condition | Status |
|---|---|
| CPU, memory and disk below warning threshold | Healthy |
| Any resource above 70% | Warning |
| Any resource above 90% | Critical |

---

## 3. Historical Monitoring

System metrics are stored in PostgreSQL and can be viewed as historical graphs.

The dashboard provides separate graphs for:

- CPU usage
- Memory usage
- Disk usage

The frontend automatically refreshes the historical data.

---

## 4. AI Anomaly Detection

The system includes an anomaly detection service that analyzes collected system metrics.

It evaluates:

- CPU behavior
- Memory behavior
- Disk behavior

The dashboard displays the resulting state as:

- Normal
- Warning
- Anomaly

This provides an additional layer beyond simple threshold-based monitoring.

---

## 5. SSH Security Monitoring

The platform monitors SSH authentication events from Linux system logs.

The collector detects:

- Successful SSH login
- Failed SSH login
- Invalid user attempts

Each detected event can contain:

- Event type
- Username
- Source IP address
- Original log message
- Event timestamp

Duplicate journal entries are prevented from being stored repeatedly.

---

## 6. PostgreSQL Database

The collected information is stored in PostgreSQL.

### System Metrics

The `system_metrics` table stores:

- ID
- Hostname
- IP address
- Operating system
- Kernel version
- CPU usage
- Memory usage
- Disk usage
- Uptime
- Collection timestamp

### SSH Events

The `ssh_events` table stores:

- ID
- Event type
- Username
- Source IP
- SSH log message
- Event timestamp

---

# 🏗️ System Architecture

```text
                  Remote RHEL Linux System
                  ┌────────────────────────┐
                  │                        │
                  │ CPU                    │
                  │ Memory                 │
                  │ Disk                   │
                  │ System Information     │
                  │ SSH Logs               │
                  │                        │
                  └───────────┬────────────┘
                              │
                         SSH / Logs
                              │
                              ▼
                  ┌────────────────────────┐
                  │       Collectors       │
                  │                        │
                  │ Remote Collector       │
                  │ SSH Collector           │
                  └───────────┬────────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │      PostgreSQL        │
                  │                        │
                  │ system_metrics         │
                  │ ssh_events             │
                  └───────────┬────────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │       FastAPI          │
                  │        Backend         │
                  │                        │
                  │ /health                │
                  │ /metrics               │
                  │ /metrics/history       │
                  │ /anomalies             │
                  │ /hosts                 │
                  │ /ssh/events            │
                  └───────────┬────────────┘
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
       ┌─────────────────┐       ┌─────────────────┐
       │ AI Anomaly      │       │ Web Dashboard   │
       │ Detection       │       │                 │
       │                 │       │ Health          │
       │ CPU             │       │ Charts          │
       │ Memory          │       │ AI Status       │
       │ Disk            │       │ SSH Events      │
       └─────────────────┘       └─────────────────┘
