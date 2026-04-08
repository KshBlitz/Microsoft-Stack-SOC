# Day 29 – SOAR Automation (Microsoft Sentinel Playbooks)

---

## Objective

Understand how **SOAR (Security Orchestration, Automation, and Response)** automates SOC workflows to reduce manual effort, improve response speed, and enforce consistent incident handling in enterprise environments.

This is the stage where SOC moves from **detection → action**.

---

## 1. Concept Overview

SOAR automation in enterprise SOC refers to:

> Automatically executing predefined response actions when a security alert or incident is triggered.

Instead of analysts manually performing repetitive tasks, automation handles:

* enrichment
* correlation
* response actions
* notification

---

## 2. Why SOAR Exists in Enterprise Security

Modern SOC challenges:

* High alert volume (alert fatigue)
* Slow manual response
* Human inconsistency
* SLA pressure

SOAR solves:

| Problem               | Solution               |
| --------------------- | ---------------------- |
| Too many alerts       | Automated triage       |
| Slow response         | Instant actions        |
| Analyst workload      | Reduced manual effort  |
| Inconsistent handling | Standardized playbooks |

---

## 3. Architecture Context

SOAR sits **after detection** in the SOC pipeline.

```
Endpoint Activity
↓
Microsoft Defender Detection
↓
Log Analytics Workspace
↓
Microsoft Sentinel Analytics Rule
↓
Alert
↓
Incident
↓
SOAR Playbook (Automation)
↓
SOC Investigation / Response
↓
ServiceNow Ticket
```

SOAR is the **execution layer of SOC**.

---

## 4. Core Components

### 4.1 Playbooks (Automation Workflows)

* Built using **Azure Logic Apps**
* Triggered by:

  * Alert creation
  * Incident creation
  * Manual execution

---

### 4.2 Triggers

Examples:

* When incident is created
* When alert is triggered
* Scheduled automation

---

### 4.3 Actions

Automation steps:

* Enrich IP
* Query logs
* Disable user
* Block IP
* Send email / Teams alert
* Create ServiceNow ticket

---

### 4.4 Connectors

Integration with:

* Microsoft Defender
* Microsoft Entra ID
* Threat Intelligence APIs
* ServiceNow
* Email / Teams

---

## 5. Log Sources / Data Sources

SOAR does not generate logs — it **consumes and acts on them**.

Key sources:

* SigninLogs (identity)
* DeviceEvents (endpoint)
* AzureActivity (cloud)
* Threat Intelligence feeds

---

## 6. Detection Logic → Automation Logic

SOAR does NOT detect threats.

It acts **after detection**.

---

### Detection → SOAR Flow

```
Detection Rule (KQL)
↓
Alert Triggered
↓
Incident Created
↓
Playbook Executes
```

---

### Example Playbook Logic (Given)

```
Alert Trigger
↓
Enrich IP
↓
Check threat intel
↓
Disable account
↓
Notify SOC
```

---

### What This Means Practically

1. Alert fires (e.g., suspicious login)
2. Playbook starts automatically
3. Extract IP from alert
4. Query threat intelligence
5. If malicious:

   * disable account
   * block IP
6. Notify SOC team

---

## 7. Investigation Workflow (With SOAR)

### Traditional SOC

```
Alert → Analyst → Investigation → Action
```

---

### SOAR-Enabled SOC

```
Alert
↓
SOAR Enrichment
↓
Preliminary Decision
↓
Analyst Investigation (if needed)
↓
Response
```

---

### Step-by-Step Investigation Thinking

1. What triggered the alert?
2. What enrichment data was added automatically?
3. Did SOAR already take action?
4. Is the action correct or needs rollback?
5. What is the impact?

---

## 8. Common Attack Scenarios Using SOAR

### 8.1 Brute Force Attack

Automation:

* Detect failed logins
* Enrich IP reputation
* Block IP if malicious

---

### 8.2 Phishing Compromise

Automation:

* Detect suspicious login
* Disable account
* Reset password
* Notify user & SOC

---

### 8.3 Malware Execution

Automation:

* Detect malicious process
* Isolate device
* Collect forensic data

---

### 8.4 Privilege Escalation

Automation:

* Detect role change
* Validate user
* Remove privilege if suspicious

---

## 9. SOC Analyst Responsibilities

### L1 Analyst

* Review SOAR actions
* Validate automation decisions
* Close false positives
* Escalate if needed

---

### L2 Analyst

* Design playbooks
* Improve automation logic
* Handle complex cases
* Tune automation conditions

---

## 10. Detection Example + SOAR Integration

### Detection (KQL)

```
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by IPAddress, bin(TimeGenerated,5m)
| where FailedAttempts > 10
```

---

### SOAR Action

If triggered:

* Extract IPAddress
* Query threat intelligence API
* If malicious:

  * Block IP in firewall
  * Create incident note
  * Notify SOC

---

## 11. False Positive Considerations

Automation risks:

* Blocking legitimate users
* Disabling admin accounts
* Overreacting to benign anomalies

---

### Example False Positives

* VPN IP triggering alerts
* Security testing activity
* Bulk login failures during outages

---

## 12. Tuning Strategy

Key tuning approaches:

### Conditional Logic

Instead of auto-response:

```
IF IP reputation = malicious
THEN disable account
ELSE notify only
```

---

### Allow Lists

Exclude:

* trusted IPs
* service accounts
* known automation systems

---

### Approval Workflow

Critical actions require:

* analyst approval before execution

---

## 13. Key Terminology

* SOAR
* Playbook
* Automation Rule
* Trigger
* Action
* Connector
* Enrichment
* Orchestration
* Response Automation

---

## 14. Interview Talking Points

1. SOAR automates post-detection response in SOC environments.
2. It integrates multiple systems like Sentinel, Defender, and ServiceNow.
3. Playbooks are built using Azure Logic Apps.
4. SOAR improves response time and reduces analyst workload.
5. Proper tuning is critical to avoid automated false positives.

---

## 15. Real Enterprise Insight

SOAR is powerful but dangerous if misconfigured.

Bad automation =

* mass account lockouts
* business disruption
* incident escalation

Good SOC teams:

* start with enrichment automation
* gradually enable response actions
* always include safeguards

---

## 16. GitHub Documentation Section

# Day 29 – SOAR Automation

## Objective

Understand how SOAR automates SOC workflows and incident response actions.

## Architecture Context

Detection → Alert → Incident → SOAR Playbook → Response

## Core Components

Playbooks, triggers, actions, connectors.

## Log Sources

SigninLogs, DeviceEvents, AzureActivity, threat intelligence feeds.

## Detection Logic

SOAR acts after detection rules trigger alerts.

## Investigation Workflow

SOAR enriches data → analyst validates → response executed.

## Example Detection

Brute force detection with automated IP enrichment and blocking.

## False Positives

VPNs, testing activity, legitimate login spikes.

## Detection Tuning

Conditional logic, allow lists, approval workflows.

## Real Attack Scenario

Suspicious login → IP enrichment → malicious → account disabled.

## SOC Analyst Responsibilities

L1 validates automation, L2 designs and tunes playbooks.

## Key Takeaways

SOAR is the execution engine of SOC that enables fast, consistent, and scalable incident response.

---

## Final Mental Model

```
Detection finds the problem
↓
SOAR decides what to do
↓
Automation executes response
↓
SOC validates and investigates
```

---

This topic directly connects with your previous days:

* Detection Engineering → triggers SOAR
* Threat Intelligence → enriches SOAR decisions
* ServiceNow → receives SOAR outcomes

This is where SOC becomes **operational, not just analytical**.

---
