# Enterprise SOC Learning – Microsoft Security Operations Deep Dive

## Overview

This repository documents a structured learning project focused on understanding how **enterprise Security Operations Centers (SOC)** operate within the Microsoft security ecosystem.

The project explores the architecture, detection logic, investigation methodology, and operational workflows used by SOC teams to detect and respond to security incidents in enterprise environments.

Rather than focusing only on tools, this repository emphasizes the **analytical thinking, investigation processes, and operational structure** followed in real SOC environments.

---

## What This Repository Covers

This project explores the core components of the Microsoft enterprise security stack:

* **Microsoft Sentinel (SIEM)** for centralized log analysis and detection
* **Microsoft Defender for Endpoint (EDR)** for endpoint telemetry and threat detection
* **Microsoft Entra ID** for identity monitoring and authentication logs
* **Azure Activity Logs** for cloud security monitoring
* **ServiceNow** for enterprise incident management
* **SOAR playbooks** for automated security response

It also covers the **SOC investigation lifecycle**, including:

* Security architecture and log ingestion
* Detection engineering using **KQL**
* Alert triage and incident investigation
* Threat intelligence enrichment
* SOC runbooks and investigation procedures
* Incident documentation and reporting
* Enterprise SOC ticketing workflows

---

## Enterprise SOC Workflow

Typical enterprise SOC operations follow a structured investigation pipeline:

```
Security Event
↓
Detection Rule
↓
Alert
↓
Alert Triage
↓
Incident Creation
↓
SOC Investigation
↓
Threat Intelligence Enrichment
↓
ServiceNow Ticket
↓
Incident Resolution
```

This repository explores each stage of this workflow.

---

## Repository Structure

The repository is organized around major areas of SOC operations:

```
enterprise-soc-learning
│
├── SOC-Architecture
├── Detection-Engineering
├── Sentinel-Operations
├── Endpoint-Investigation
├── Identity-Investigation
├── Cloud-Security
├── Email-Security
├── SOC-Runbooks
├── Detection-Rules
├── Case-Studies
└── SOC-Investigation-Reports
```

Each section contains documentation, detection queries, or investigation examples related to that area.

---

## Skills Developed

This project focuses on building knowledge in the following areas:

* Enterprise SOC architecture
* Detection engineering using KQL
* Security event correlation
* Alert triage methodology
* Endpoint and identity investigation
* Threat intelligence usage
* Runbook-driven incident response
* SOC incident documentation

---

## Purpose of This Repository

The goal of this repository is to build a **SOC engineering learning portfolio** that demonstrates understanding of:

* Microsoft enterprise security architecture
* SOC investigation workflows
* detection engineering concepts
* incident investigation methodology
* enterprise security operations processes

---
