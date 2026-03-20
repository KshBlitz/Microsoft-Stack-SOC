# Day 14 – Detection Lifecycle

---

# 1. Concept Overview

The **Detection Lifecycle** represents how a security detection evolves inside an enterprise SOC environment — from an idea to a fully operational detection that produces alerts, incidents, and is continuously improved.

```
Detection Idea
↓
Query (KQL)
↓
Analytics Rule
↓
Alert
↓
Incident
↓
Tuning & Optimization
```

This lifecycle is **not linear** — it is a **continuous feedback loop** driven by:

- SOC analyst feedback
- False positives
- New attack techniques
- Environment changes

---

# 2. Why This Exists in Enterprise Security

Detection lifecycle exists because:

- Raw logs alone **do not provide security**
- Detection must be **engineered, tested, and refined**
- Attack techniques constantly evolve
- Static detections become ineffective over time

### Core Problems It Solves

- Converts **raw telemetry → actionable security signals**
- Reduces **alert fatigue**
- Improves **detection accuracy**
- Enables **continuous security improvement**

---

# 3. Architecture Context

The detection lifecycle operates across the Microsoft security ecosystem:

```
Endpoint / Identity / Cloud Activity
↓
Microsoft Defender (Telemetry Generation)
↓
Log Analytics Workspace (Data Storage)
↓
KQL Query (Detection Logic)
↓
Microsoft Sentinel Analytics Rule
↓
Alert
↓
Incident (Grouped Alerts)
↓
SOC Investigation
↓
Tuning & Feedback Loop
```

This aligns directly with enterprise SOC pipelines :contentReference[oaicite:0]{index=0}

---

# 4. Core Components of Detection Lifecycle

## 4.1 Detection Idea

The starting point.

Sources of detection ideas:

- Threat intelligence
- MITRE ATT&CK techniques
- Incident learnings
- Threat hunting discoveries
- Red team simulations

Example:

> "Detect multiple failed logins from same IP"

---

## 4.2 Query (KQL)

Transforms idea into logic.

- Written using **Kusto Query Language (KQL)**
- Operates on logs like:
  - `SigninLogs`
  - `DeviceProcessEvents`
  - `SecurityEvent`

Example:

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by IPAddress, bin(TimeGenerated, 5m)
| where FailedAttempts > 10
```

---

## 4.3 Analytics Rule (Microsoft Sentinel)

Turns query into a **scheduled detection mechanism**

Key configurations:

- Frequency (e.g., every 5 min)
- Lookback window (e.g., last 1 hour)
- Thresholds
- Severity (Low / Medium / High / Critical)
- Entity mapping (User, IP, Host)

---

## 4.4 Alert

Generated when rule conditions are met.

Contains:

- Detection name
- Entities (user, IP, device)
- Timestamp
- Severity
- Evidence (logs)

Alerts are **atomic signals**.

---

## 4.5 Incident

- Grouping of related alerts
- Represents a **potential security case**

Why incidents exist:

- Reduce alert noise
- Provide investigation context
- Enable correlation across sources

Example:

```
Multiple failed logins
+
Suspicious successful login
+
PowerShell execution
=
1 Incident
```

---

## 4.6 Tuning (Continuous Improvement)

Most critical stage.

Includes:

- Reducing false positives
- Adjusting thresholds
- Excluding known benign activity
- Improving detection logic

---

# 5. Log Sources / Data Sources

Detection lifecycle relies on telemetry from:

### Identity Logs
- `SigninLogs`
- `AuditLogs`

### Endpoint Logs
- `DeviceProcessEvents`
- `DeviceEvents`
- `DeviceNetworkEvents`

### Cloud Logs
- `AzureActivity`

### Email Logs
- `OfficeActivity`

---

# 6. Detection Logic (Engineering Mindset)

Detection logic must include:

## 6.1 Threshold-Based Detection

Example:

- Failed logins > 10 in 5 minutes

## 6.2 Time Window Logic

```kql
bin(TimeGenerated, 5m)
```

## 6.3 Behavioral Detection

- Rare processes
- Unusual login locations

## 6.4 Correlation Logic

Combine multiple signals:

```
Failed login
+
Successful login
+
Process execution
```

---

# 7. Investigation Workflow

When an alert is generated:

```
Alert Triggered
↓
L1 Initial Triage
↓
Log Correlation
↓
Entity Analysis
↓
Threat Validation
↓
Escalation or Closure
```

---

## Step-by-Step SOC Thinking

### Step 1: What happened?
- What triggered the detection?

### Step 2: Who is involved?
- User
- IP address
- Device

### Step 3: Is activity suspicious?
- Compare with baseline behavior

### Step 4: Any follow-up activity?
- Lateral movement?
- Privilege escalation?

### Step 5: Confirm True/False Positive

---

# 8. Common Attack Scenarios

## 8.1 Brute Force Attack

```
Multiple failed logins
↓
Successful login
↓
Account compromise
```

---

## 8.2 Phishing Attack

```
Email delivered
↓
User clicks link
↓
Credential theft
↓
Suspicious login
```

---

## 8.3 Malware Execution

```
User downloads file
↓
Process execution
↓
Command & Control communication
```

---

## 8.4 Privilege Escalation

```
User gains admin rights
↓
Access sensitive resources
```

---

# 9. SOC Analyst Responsibilities

## L1 Analyst

- Monitor alerts
- Perform initial triage
- Validate basic indicators
- Escalate suspicious cases

---

## L2 Analyst

- Deep investigation
- Cross-log correlation
- Detection tuning
- Threat confirmation
- Improve detection rules

---

# 10. Detection Example

## Scenario: Suspicious PowerShell Execution

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "powershell"
| where ProcessCommandLine contains "-enc"
```

### Detection Logic

- Encoded PowerShell commands
- Common attacker technique

---

# 11. False Positive Considerations

Common benign cases:

- Admin scripts
- IT automation tools
- Security tools
- Scheduled tasks

---

# 12. Tuning Strategy

## 12.1 Exclusions

- Trusted IP addresses
- Service accounts

## 12.2 Threshold Adjustment

- Increase/decrease detection limits

## 12.3 Context Enrichment

- Add user role
- Add device criticality

## 12.4 Behavioral Baseline

- Compare against normal activity

---

# 13. Key Terminology

- Detection Engineering
- Analytics Rule
- Alert Correlation
- Incident Management
- False Positive
- Threat Intelligence
- Log Analytics Workspace
- KQL Querying
- SIEM Operations
- SOC Workflow

---

# 14. Interview Talking Points

1. Detection lifecycle starts from an idea and evolves through continuous tuning.
2. KQL queries convert security ideas into executable detection logic.
3. Alerts are individual signals, while incidents group related alerts.
4. Detection tuning is critical to reduce false positives in enterprise SOC.
5. Effective detection requires correlation across identity, endpoint, and cloud logs.

---

# 15. GitHub Documentation Section

## Day 14 – Detection Lifecycle

### Objective
Understand how detections are created, executed, and improved in an enterprise SOC.

---

### Architecture Context

```
Log Source
↓
Log Analytics Workspace
↓
KQL Query
↓
Sentinel Analytics Rule
↓
Alert
↓
Incident
↓
SOC Investigation
↓
Tuning
```

---

### Core Components

- Detection Idea
- KQL Query
- Analytics Rule
- Alert
- Incident
- Tuning

---

### Log Sources

- SigninLogs
- DeviceProcessEvents
- AzureActivity
- OfficeActivity

---

### Detection Logic

- Threshold-based detection
- Time-window analysis
- Behavioral detection
- Multi-source correlation

---

### Investigation Workflow

- Alert triage
- Entity analysis
- Log correlation
- Threat validation

---

### Example Detection

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by IPAddress, bin(TimeGenerated,5m)
| where FailedAttempts > 10
```

---

### False Positives

- Admin activity
- Automation scripts
- Trusted IP ranges

---

### Detection Tuning

- Exclude known benign entities
- Adjust thresholds
- Improve logic

---

### Real Attack Scenario

Brute force → successful login → suspicious activity → incident creation

---

### SOC Analyst Responsibilities

- L1: Triage alerts
- L2: Investigate and tune detections

---

### Key Takeaways

- Detection lifecycle is continuous
- Tuning is critical for effectiveness
- Correlation across logs improves accuracy
- Alerts → Incidents → Investigation → Improvement loop

---

This is the **core backbone of enterprise SOC detection engineering** and directly impacts how effectively a SOC can detect and respond to threats in real environments.