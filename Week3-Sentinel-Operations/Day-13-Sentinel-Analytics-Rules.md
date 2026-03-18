# Day 13 – Microsoft Sentinel Analytics Rules (Detection Engineering Deep Dive)

---

# Objective

Understand how **Microsoft Sentinel Analytics Rules** power detection engineering in enterprise SOC environments — from raw telemetry to actionable security incidents.

This is the **core detection engine** of a SIEM-driven SOC.

---

# 1. Concept Overview

Analytics Rules in Microsoft Sentinel are **detection logic configurations** that analyze incoming telemetry and generate:

```
Log Data → Detection Rule → Alert → Incident
```

They convert **raw logs into security signals**.

Without analytics rules:

* Logs = noise
* No detection = no SOC

With analytics rules:

* Logs → intelligence
* Detection → investigation

---

# 2. Why This Exists in Enterprise Security

Enterprise environments generate:

* Millions of events per day
* Across identity, endpoint, cloud, email

Manual monitoring is impossible.

Analytics rules exist to:

* Automatically detect threats
* Reduce analyst workload
* Standardize detection logic
* Enable scalable SOC operations

---

# 3. Architecture Context

Full detection pipeline:

```
Endpoint / Identity / Cloud Activity
↓
Microsoft Defender / Azure Logs
↓
Log Analytics Workspace
↓
Sentinel Analytics Rule
↓
Alert
↓
Incident (Grouped Alerts)
↓
SOC Investigation
↓
ServiceNow Ticket
```

This sits at the **core of SIEM operations** 

---

# 4. Types of Analytics Rules

## 4.1 Scheduled Rules (Most Important)

* Run every X minutes
* Query logs using KQL
* Detect patterns over time

Used for:

* Brute force detection
* Rare process detection
* Suspicious logins

---

## 4.2 Near Real-Time (NRT)

* Trigger instantly
* Minimal delay

Used for:

* High-risk activities
* Critical alerts

---

## 4.3 Fusion Rules

* ML-based correlation
* Combine multiple signals

Used for:

* Advanced attack chains
* Multi-stage attacks

---

# 5. Core Components of an Analytics Rule

## Rule Structure

### 1. Query

KQL logic defining detection

### 2. Frequency

How often rule runs
Example: every 5 minutes

### 3. Lookback Window

How much past data is analyzed
Example: last 30 minutes

---

### 4. Threshold

When to trigger alert

Example:

```
FailedAttempts > 10
```

---

### 5. Entity Mapping

Critical for investigation:

* User
* IP
* Host
* Process

This powers:

* Incident graph
* Investigation timeline

---

### 6. Alert Details

* Severity (Low / Medium / High / Critical)
* Tactics (MITRE ATT&CK)
* Description

---

# 6. Log Sources / Data Sources

Analytics rules rely on telemetry from:

## Identity

* SigninLogs
* AuditLogs

## Endpoint

* DeviceProcessEvents
* DeviceNetworkEvents

## Cloud

* AzureActivity

## Email

* OfficeActivity

---

# 7. Detection Logic (How Rules Actually Work)

Detection engineering mindset:

---

## 7.1 Threshold-Based Detection

Example:

```
Multiple failed logins → possible brute force
```

---

## 7.2 Time Window Logic

```
10 failures within 5 minutes
```

---

## 7.3 Behavioral Detection

```
Rare process execution
```

---

## 7.4 Correlation Logic

```
Failed login + successful login + PowerShell execution
```

---

# 8. Investigation Workflow

When an alert is triggered:

---

## Step 1 – Validate Alert

* What rule triggered?
* What condition matched?

---

## Step 2 – Identify Entities

* User
* Device
* IP

---

## Step 3 – Correlate Logs

Check:

* Other login attempts
* Process activity
* Network connections

---

## Step 4 – Timeline Reconstruction

```
Login → Execution → Lateral Movement
```

---

## Step 5 – Determine Verdict

* False Positive
* Suspicious
* Confirmed Attack

---

## Step 6 – Take Action

* Escalate
* Contain
* Close

---

# 9. Common Attack Scenarios

Analytics rules detect:

---

## Brute Force Attack

* Many failed logins
* Same IP

---

## Credential Compromise

* Failed + successful login
* New location

---

## Malware Execution

* Suspicious process
* Encoded PowerShell

---

## Lateral Movement

* Remote execution tools
* Multiple hosts accessed

---

# 10. Detection Example (KQL)

## Brute Force Detection

```
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

---

## What This Does

* Filters failed logins
* Groups by IP
* Detects high frequency attempts

---

# 11. False Positive Considerations

Common benign scenarios:

* VPN reconnect loops
* Misconfigured applications
* Password sync issues
* Load testing

---

# 12. Detection Tuning Strategy

Real SOCs ALWAYS tune rules.

---

## 12.1 Exclusions

* Trusted IPs
* Service accounts

---

## 12.2 Threshold Adjustment

```
10 → 20 attempts
```

---

## 12.3 Time Window Changes

```
5 min → 10 min
```

---

## 12.4 Context Enrichment

Add:

* Geo location
* User risk level

---

# 13. SOC Analyst Responsibilities

---

## L1 Analyst

* Monitor alerts
* Perform triage
* Validate rule trigger
* Escalate if needed

---

## L2 Analyst

* Investigate deeply
* Correlate logs
* Tune detection rules
* Improve detection logic

---

# 14. Key Terminology

* Analytics Rule
* Detection Logic
* KQL Query
* Threshold
* Lookback Window
* Entity Mapping
* Alert vs Incident
* SIEM Detection
* Correlation
* Threat Detection

---

# 15. Interview Talking Points

---

## 1

"Analytics rules convert raw telemetry into actionable alerts using KQL-based detection logic."

---

## 2

"They operate on scheduled or real-time execution models and use thresholds and time windows to detect anomalies."

---

## 3

"Entity mapping enables investigation by linking alerts to users, devices, and IPs."

---

## 4

"Detection tuning is critical to reduce false positives in enterprise SOC environments."

---

## 5

"Analytics rules sit at the core of SIEM detection pipelines, bridging logs and incident response."

---

# 16. Real Enterprise Insight

In real SOC environments:

* 70% of alerts are noisy initially
* Continuous tuning is required
* Good detection = low noise + high signal

---

# 17. GitHub Documentation Section

## Day 13 – Sentinel Analytics Rules

### Objective

Understand how Microsoft Sentinel Analytics Rules detect threats and generate alerts.

---

### Architecture Context

```
Log Source → Log Analytics → Sentinel Rule → Alert → Incident → SOC
```

---

### Core Components

* KQL Query
* Frequency
* Lookback Window
* Threshold
* Entity Mapping

---

### Detection Logic

* Threshold-based detection
* Time window logic
* Behavioral anomalies
* Cross-log correlation

---

### Investigation Workflow

1. Validate alert
2. Identify entities
3. Correlate logs
4. Build timeline
5. Decide verdict

---

### Example Detection

Brute force login detection using SigninLogs.

---

### False Positives

* VPN issues
* Misconfigured systems

---

### Detection Tuning

* Exclusions
* Threshold adjustments
* Context enrichment

---

### Key Takeaways

* Analytics rules are the **core detection engine of Sentinel**
* They transform logs into alerts
* Detection quality depends on tuning
* SOC analysts rely heavily on these rules for investigations

---

# Final Understanding

If you understand Analytics Rules deeply, you understand:

* How detection engineering works
* How SOC alerts are generated
* How investigations begin
* How enterprise SIEM actually operates

This is **one of the most important concepts in the entire SOC ecosystem** 

---
