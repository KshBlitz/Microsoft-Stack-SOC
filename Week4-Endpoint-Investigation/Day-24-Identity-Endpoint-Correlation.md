# Day 24 – SOC Investigation Runbooks (Enterprise Level)

---

## Objective

Understand how **SOC investigation runbooks standardize incident response** and enable analysts to perform **consistent, repeatable, and high-quality investigations** across enterprise environments.

Runbooks are critical for:

* reducing investigation time
* ensuring no steps are missed
* enabling L1 → L2 escalation clarity
* maintaining SOC operational maturity

This directly aligns with enterprise SOC workflow design described in the project structure  and Day 24 learning plan .

---

# 1. Concept Overview

A **SOC Investigation Runbook** is a **step-by-step procedural guide** used by analysts to investigate a specific type of alert or incident.

Think of it as:

```
Detection → Investigation Steps → Decision → Action
```

It transforms **analyst thinking into a structured workflow**.

---

# 2. Why Runbooks Exist in Enterprise Security

Without runbooks:

* investigations are inconsistent
* junior analysts miss critical steps
* response time increases
* incident quality varies

Runbooks solve:

| Problem               | Solution                   |
| --------------------- | -------------------------- |
| Analyst inconsistency | Standardized workflow      |
| Skill gap             | Guided investigation steps |
| Slow response         | Predefined actions         |
| Missed indicators     | Checklist-based validation |

---

# 3. Architecture Context

Runbooks operate at the **SOC Investigation layer**:

```
Endpoint / Identity Activity
↓
Microsoft Defender / Entra Logs
↓
Log Analytics Workspace
↓
Microsoft Sentinel Rule
↓
Alert
↓
Incident
↓
SOC Investigation (RUNBOOK EXECUTION)
↓
ServiceNow Ticket / Response
```

Runbooks are where **human + process + telemetry meet**.

---

# 4. Core Components of a Runbook

Every enterprise-grade runbook includes:

### 1. Trigger Condition

* What alert initiates this runbook
* Example: "Multiple failed login attempts"

### 2. Data Sources

* Logs used during investigation

  * SigninLogs
  * AuditLogs
  * DeviceEvents

### 3. Investigation Steps

* Ordered logical steps

### 4. Decision Points

* Is this malicious or benign?

### 5. Actions

* Contain, escalate, or close

### 6. Documentation Requirements

* Evidence to record in ticket

---

# 5. Types of SOC Runbooks

### Identity-Based

* Brute force
* Impossible travel
* MFA bypass

### Endpoint-Based

* Malware execution
* Suspicious process

### Email-Based

* Phishing

### Cloud-Based

* Privilege escalation
* Azure activity anomalies

---

# 6. Deep Dive Example – Brute Force Investigation Runbook

---

## Scenario

Detection triggered:

```
Multiple failed login attempts from same IP
```

---

## Full Enterprise Runbook

### Step 1 – Validate Detection

**Goal:** Confirm alert is valid

Check:

```
SigninLogs
| where ResultType != 0
```

Look for:

* repeated failures
* same IP
* multiple users

---

### Step 2 – Analyze Source IP

Questions:

* Is IP external or internal?
* Known malicious?
* Seen before in environment?

Actions:

* Threat intelligence lookup
* Geo-location check
* ASN analysis

---

### Step 3 – Identify Targeted Accounts

Check:

```
| summarize count() by UserPrincipalName
```

Look for:

* single user → targeted attack
* multiple users → password spraying

---

### Step 4 – Check for Successful Login

Critical pivot:

```
SigninLogs
| where ResultType == 0
```

If success exists:

→ HIGH RISK

---

### Step 5 – Correlate with User Activity

After successful login:

Check:

* Device access
* Email activity
* File access
* Privilege changes

Tables:

* AuditLogs
* OfficeActivity
* DeviceEvents

---

### Step 6 – Timeline Reconstruction

Build sequence:

```
Failed logins → Success → Post-login actions
```

This is **attack confirmation phase**.

---

### Step 7 – Determine Compromise

| Condition                     | Conclusion           |
| ----------------------------- | -------------------- |
| Only failures                 | Likely benign scan   |
| Failures + success            | Possible compromise  |
| Success + suspicious activity | Confirmed compromise |

---

### Step 8 – Response Actions

If compromised:

* Disable account
* Force password reset
* Revoke sessions
* Enable MFA

If benign:

* Close as false positive

---

### Step 9 – Documentation

Record:

* IP address
* user affected
* timeline
* actions taken

---

# 7. Investigation Thinking Model

Runbooks follow a **core SOC thinking pattern**:

```
What happened?
↓
Who is involved?
↓
Where did it come from?
↓
Was access successful?
↓
What happened after access?
↓
Is it malicious?
↓
What action is required?
```

---

# 8. Detection Logic Behind Runbook

Example detection:

```
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by IPAddress, bin(TimeGenerated,5m)
| where FailedAttempts > 10
```

### Detection Principles:

* Threshold-based (10 attempts)
* Time-window based (5 minutes)
* Behavior anomaly (repeated failures)

---

# 9. Common Attack Variants

### Password Spraying

* many users, few attempts each

### Credential Stuffing

* known credentials reused

### Targeted Brute Force

* one user, many attempts

---

# 10. False Positive Considerations

Not all brute force alerts are malicious.

Common benign scenarios:

* user typing wrong password repeatedly
* VPN reconnect attempts
* misconfigured applications
* security testing tools

---

# 11. Tuning Strategy

To reduce noise:

* exclude trusted IP ranges
* exclude service accounts
* adjust threshold (10 → 20)
* filter internal traffic

---

# 12. SOC Analyst Responsibilities

### L1 Analyst

* validate alert
* follow runbook steps
* identify obvious false positives
* escalate if suspicious

---

### L2 Analyst

* deep log correlation
* confirm compromise
* perform containment
* improve detection logic

---

# 13. Advanced Runbook Enhancements (Enterprise Level)

### 1. Automation (SOAR)

Runbook can trigger:

```
Alert
↓
Playbook
↓
IP enrichment
↓
User risk score check
↓
Auto-disable account (if high risk)
```

---

### 2. Threat Intelligence Integration

* IP reputation scoring
* known attacker infrastructure

---

### 3. Risk-Based Decision Making

Combine:

* login success
* device risk
* user behavior

---

# 14. Runbooks vs Playbooks

| Runbook             | Playbook         |
| ------------------- | ---------------- |
| Manual steps        | Automated        |
| Analyst-driven      | System-driven    |
| Investigation logic | Action execution |

---

# 15. Key Terminology

* SOC Runbook
* Investigation Workflow
* Alert Triage
* Incident Response
* Log Correlation
* Detection Engineering
* Threat Intelligence Enrichment
* Timeline Reconstruction

---

# 16. Interview Talking Points

Strong answers:

1. Runbooks standardize SOC investigations and reduce analyst error.
2. They convert detection alerts into structured investigation workflows.
3. They help L1 analysts perform consistent triage and escalation.
4. They ensure all critical evidence is collected before decision making.
5. In enterprise SOC, runbooks are often combined with SOAR automation.

---

# 17. GitHub Documentation Section

## Day 24 – SOC Investigation Runbooks

### Objective

Understand how structured runbooks guide SOC analysts in performing consistent and effective investigations.

### Architecture Context

Runbooks operate during the **SOC investigation phase after alert generation in Microsoft Sentinel**.

### Core Components

* Trigger condition
* investigation steps
* decision points
* response actions

### Log Sources

* SigninLogs
* AuditLogs
* DeviceEvents
* OfficeActivity

### Detection Logic

Threshold-based detections identify suspicious behavior such as brute force attempts.

### Investigation Workflow

* validate alert
* analyze source
* check success login
* correlate activity
* determine compromise

### Example Detection

Brute force detection using failed login threshold.

### False Positives

User mistakes, VPN retries, automated systems.

### Detection Tuning

Exclude trusted sources, adjust thresholds.

### Real Attack Scenario

Password spraying leading to account compromise.

### SOC Responsibilities

L1 performs triage, L2 performs deep investigation and response.

### Key Takeaways

Runbooks are essential for **consistent, scalable, and efficient SOC operations**.

---

# FINAL UNDERSTANDING

Runbooks are not just documentation.

They are:

→ **SOC decision engines**
→ **analyst training tools**
→ **incident quality control mechanisms**

If you master runbooks, you transition from:

**"looking at alerts" → "running structured investigations like a real SOC analyst"**
