# Day 26 – Azure Activity Monitoring

## Objective

Understand how **Azure control plane activity** is monitored using Azure Activity Logs, and how SOC analysts detect **resource manipulation, privilege changes, and infrastructure abuse** in enterprise environments.

---

# 1. Concept Overview

Azure Activity Monitoring focuses on tracking **management-level operations** performed on Azure resources.

These logs answer:

* Who created/modified/deleted a resource?
* Who changed access permissions?
* What actions were performed in the Azure environment?

Unlike endpoint logs, this is **control plane visibility**.

### Key Table

```
AzureActivity
```

This table records:

* Resource creation
* Resource deletion
* Role assignments
* Policy changes
* Subscription-level operations

---

# 2. Why This Exists in Enterprise Security

Attackers targeting cloud environments aim to:

* Create rogue resources (crypto mining, persistence)
* Escalate privileges via role assignments
* Delete logs or resources to hide activity

Azure Activity Logs exist to:

* Provide **audit visibility**
* Detect **misuse of administrative privileges**
* Enable **forensic reconstruction of cloud attacks**

---

# 3. Architecture Context

```
User / Attacker Action
↓
Azure Control Plane (ARM API)
↓
Azure Activity Logs
↓
Log Analytics Workspace
↓
Microsoft Sentinel Analytics Rule
↓
Alert
↓
Incident
↓
SOC Investigation
↓
ServiceNow Ticket
```

This sits **parallel to endpoint & identity telemetry**.

---

# 4. Core Components

### 1. Azure Resource Manager (ARM)

* Handles all control plane operations
* Every action generates a log entry

### 2. Azure Activity Logs

* Subscription-level logs
* Stored for auditing and monitoring

### 3. Log Analytics Workspace

* Central storage for logs

### 4. Microsoft Sentinel

* Detection and correlation engine

---

# 5. Log Sources / Data Sources

### Primary Table

```
AzureActivity
```

### Important Fields

| Field                 | Description               |
| --------------------- | ------------------------- |
| TimeGenerated         | When action occurred      |
| OperationNameValue    | Action performed          |
| Caller                | User or service principal |
| ResourceGroup         | Target resource group     |
| ResourceProviderValue | Service type              |
| ActivityStatusValue   | Success/Failure           |

---

# 6. Detection Logic

## Detection Categories

### 1. VM Creation Detection

* Detect unauthorized infrastructure creation

### 2. Role Assignment Detection

* Detect privilege escalation

### 3. Resource Deletion Detection

* Detect sabotage or anti-forensics

---

## Detection Thinking

### Key Questions

* Is this action expected?
* Who performed it?
* Is the identity privileged?
* Is the timing suspicious?
* Is this part of a larger attack chain?

---

# 7. Investigation Workflow

## Step-by-Step SOC Investigation

### Step 1: Identify Action

* What operation occurred?
* Example:

  * VM creation
  * Role assignment
  * Resource deletion

---

### Step 2: Identify Actor

* Check `Caller`
* Determine:

  * User account
  * Service principal
  * Automation identity

---

### Step 3: Validate Legitimacy

* Is this part of:

  * DevOps pipeline?
  * Scheduled deployment?
  * Admin activity?

---

### Step 4: Correlate Logs

Correlate with:

* SigninLogs → login source
* AuditLogs → identity changes
* Defender logs → endpoint impact

---

### Step 5: Timeline Reconstruction

```
Login
↓
Privilege change
↓
Resource creation
↓
Suspicious activity
```

---

### Step 6: Impact Assessment

* What resources were affected?
* Was data exposed?
* Was persistence established?

---

# 8. Common Attack Scenarios

### 1. Privilege Escalation

```
User compromised
↓
Assign Owner role
↓
Full tenant control
```

---

### 2. Resource Abuse (Crypto Mining)

```
Attacker login
↓
Create multiple VMs
↓
Run mining workloads
```

---

### 3. Defense Evasion

```
Attacker deletes resources/logs
↓
Removes evidence
```

---

### 4. Persistence

```
Create service principal
↓
Assign privileged role
↓
Maintain long-term access
```

---

# 9. SOC Analyst Responsibilities

## L1 Analyst

* Monitor AzureActivity alerts
* Validate:

  * user
  * action
  * timing
* Check for obvious false positives
* Escalate suspicious cases

---

## L2 Analyst

* Perform deep correlation
* Investigate:

  * identity compromise
  * privilege escalation
* Tune detection rules
* Build advanced detections

---

# 10. Detection Examples (KQL)

## 1. VM Creation Detection

```
AzureActivity
| where OperationNameValue contains "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup, ResourceId
```

---

## 2. Role Assignment Detection

```
AzureActivity
| where OperationNameValue contains "Microsoft.Authorization/roleAssignments/write"
| project TimeGenerated, Caller, ResourceGroup, ActivityStatusValue
```

---

## 3. Resource Deletion Detection

```
AzureActivity
| where OperationNameValue contains "delete"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceId
```

---

# 11. False Positive Considerations

Common legitimate scenarios:

* DevOps pipelines creating resources
* Scheduled infrastructure deployments
* Admin performing maintenance
* Automated scripts

---

# 12. Tuning Strategy

### Reduce Noise By:

* Excluding:

  * trusted service accounts
  * automation identities
* Filtering:

  * business hours vs after-hours
* Whitelisting:

  * known deployment IPs

---

### Example

```
| where Caller !in ("devops@company.com")
```

---

# 13. Key Terminology

* Azure Activity Logs
* Control Plane Monitoring
* Resource Manager (ARM)
* Role Assignment
* Privilege Escalation
* Cloud Security Monitoring
* Azure RBAC
* Infrastructure Audit Logs

---

# 14. Interview Talking Points

1. Azure Activity Logs monitor **control plane operations**, not data plane.
2. The `AzureActivity` table tracks **resource creation, deletion, and permission changes**.
3. Role assignment logs are critical for detecting **cloud privilege escalation**.
4. SOC analysts correlate AzureActivity with identity and endpoint logs for full context.
5. Detection logic focuses on **unauthorized administrative actions** and anomalies.

---

# 15. GitHub Documentation Section

## # Day 26 – Azure Activity Monitoring

### Objective

Monitor Azure control plane activity to detect unauthorized resource operations and privilege changes.

---

### Architecture Context

Azure Resource Manager → AzureActivity Logs → Log Analytics → Sentinel → Incident

---

### Core Components

* Azure Activity Logs
* ARM (Azure Resource Manager)
* Microsoft Sentinel

---

### Log Sources

* AzureActivity table

---

### Detection Logic

* VM creation detection
* Role assignment detection
* Resource deletion detection

---

### Investigation Workflow

* Identify action
* Identify actor
* Validate legitimacy
* Correlate logs
* Build timeline
* Assess impact

---

### Example Detection

* VM creation query
* Role assignment query
* Deletion detection

---

### False Positives

* DevOps activity
* Automation scripts
* Admin operations

---

### Detection Tuning

* Exclude trusted identities
* Adjust thresholds
* Filter expected operations

---

### Real Attack Scenario

Compromised user assigns Owner role and creates resources for persistence.

---

### SOC Responsibilities

* L1: triage and validation
* L2: deep investigation and tuning

---

### Key Takeaways

Azure Activity Logs are critical for detecting **cloud privilege abuse, infrastructure manipulation, and persistence mechanisms** in enterprise SOC environments.

---


