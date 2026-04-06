# Day 27 – Cloud Privilege Escalation (Azure / Microsoft Environment)

---

## 1. Concept Overview

Cloud Privilege Escalation is the process where a user, service, or identity gains **higher permissions than originally assigned** within a cloud environment.

In Microsoft Azure environments, this typically happens through:

* Role misconfigurations
* Excessive permissions
* Misuse of IAM (Identity & Access Management)
* Exploiting trust relationships

### Example

```
Contributor → Owner role
```

This means a user who could only manage resources now gains **full control including access management**, which is critical.

---

## 2. Why This Exists in Enterprise Security

Privilege escalation is one of the **most dangerous attack stages** because:

* It allows attackers to **take control of the environment**
* Enables:

  * Data exfiltration
  * Persistence
  * Lateral movement
  * Security control bypass

### Real Risk

If an attacker gets **Owner role**, they can:

* Assign roles to themselves
* Disable logging
* Delete resources
* Access secrets

---

## 3. Architecture Context

Cloud privilege escalation sits in the **Identity + Cloud Control Plane layer**

```
User / Identity Activity
↓
Microsoft Entra ID (Authentication + Roles)
↓
Azure Resource Manager (Authorization)
↓
Azure Activity Logs
↓
Log Analytics Workspace
↓
Microsoft Sentinel Detection Rule
↓
Alert → Incident
↓
SOC Investigation
↓
ServiceNow Ticket
```

---

## 4. Core Components

### 1. Microsoft Entra ID

* Handles authentication
* Stores identities (users, service principals)

### 2. Azure RBAC (Role-Based Access Control)

* Defines permissions
* Assigns roles like:

  * Reader
  * Contributor
  * Owner

### 3. Azure Resource Manager (ARM)

* Executes actions on resources
* Enforces permissions

### 4. Role Assignments

* Link between:

  * Identity
  * Role
  * Scope (subscription/resource group/resource)

---

## 5. Log Sources / Data Sources

### Primary Logs

#### AzureActivity

* Tracks control plane actions
* Key for privilege escalation detection

#### AuditLogs (Entra ID)

* Tracks identity changes
* Role assignments
* Directory changes

#### SigninLogs

* Who logged in
* From where

---

### Important Operations to Monitor

* `Microsoft.Authorization/roleAssignments/write`
* `Add member to role`
* `Update role assignment`
* `Assign Owner role`

---

## 6. Detection Logic

### Detection Idea

Detect when:

* A user gains **higher privilege role**
* A role is assigned **outside normal behavior**
* A **rare role assignment occurs**

---

### Detection Strategy

#### 1. Role Elevation Detection

* Identify privilege jump
* Example:

  * Contributor → Owner

#### 2. Rare Activity Detection

* Role assignment not seen before

#### 3. Time-based anomaly

* Role assignment at unusual hours

#### 4. Identity anomaly

* New IP / location

---

## 7. Investigation Workflow

### Step 1 – Identify the Alert

* Who received elevated role?
* What role was assigned?

---

### Step 2 – Validate Actor

* Who assigned the role?
* Is it:

  * Admin?
  * Service account?
  * Compromised user?

---

### Step 3 – Timeline Analysis

Check:

* Login before role assignment
* Source IP
* Device

---

### Step 4 – Scope Impact

* Subscription?
* Resource group?
* Critical resource?

---

### Step 5 – Check Post-Escalation Activity

After privilege gain, check:

* Resource creation
* VM access
* Key vault access
* Data downloads

---

### Step 6 – Determine Intent

* Legitimate admin change?
* Misconfiguration?
* Malicious escalation?

---

## 8. Common Attack Scenarios

### 1. Credential Compromise + Role Assignment

```
Phishing
↓
Account compromise
↓
Attacker logs in
↓
Assigns Owner role
↓
Full control
```

---

### 2. Misconfigured Permissions Abuse

* User already has:

  * `Microsoft.Authorization/*`
* Can assign roles to themselves

---

### 3. Service Principal Abuse

* Compromised app identity
* Escalates privileges silently

---

### 4. Insider Threat

* Admin intentionally escalates access

---

## 9. SOC Analyst Responsibilities

### L1 Analyst

* Validate alert
* Identify:

  * User
  * Role
  * Time
* Check if activity is expected
* Escalate if suspicious

---

### L2 Analyst

* Deep investigation
* Correlate:

  * SigninLogs
  * AuditLogs
  * AzureActivity
* Check attacker behavior post-escalation
* Recommend remediation

---

## 10. Detection Example (KQL)

### Role Assignment Detection

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| project TimeGenerated, Caller, ResourceGroup, ActivityStatusValue
```

---

### Detect Owner Role Assignment

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| where Properties contains "Owner"
| project TimeGenerated, Caller, Properties
```

---

### Rare Role Assignment

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| summarize count() by Caller, bin(TimeGenerated,1d)
| where count_ < 3
```

---

## 11. False Positive Considerations

Legitimate scenarios:

* Admin onboarding new user
* DevOps automation assigning roles
* Infrastructure deployment scripts
* Scheduled access changes

---

## 12. Tuning Strategy

### Reduce Noise

* Exclude:

  * Known admin accounts
  * Automation accounts
* Maintain allowlist

---

### Improve Detection

* Alert only on:

  * High privilege roles (Owner, User Access Administrator)
* Add:

  * Time anomaly checks
  * IP anomaly checks

---

## 13. Key Terminology

* RBAC (Role-Based Access Control)
* Role Assignment
* Privilege Escalation
* Azure Activity Logs
* Identity Abuse
* Control Plane Activity
* Least Privilege Principle
* Owner Role
* Contributor Role
* Access Scope

---

## 14. Interview Talking Points

* Privilege escalation in Azure occurs mainly through **RBAC misconfigurations**
* The most critical event is **roleAssignments/write**
* AzureActivity logs are primary source for detecting role changes
* Escalation risk increases when **Contributor gains Owner role**
* Detection requires **correlation of identity + activity logs**

---

## 15. GitHub Documentation Section

# Day 27 – Cloud Privilege Escalation

## Objective

Understand how privilege escalation occurs in Azure and how SOC detects and investigates it.

## Architecture Context

Entra ID → Azure RBAC → Azure Activity Logs → Sentinel → Incident Response

## Core Components

* Entra ID
* Azure RBAC
* Role Assignments
* Azure Resource Manager

## Log Sources

* AzureActivity
* AuditLogs
* SigninLogs

## Detection Logic

Detect role assignment events and privilege elevation patterns.

## Investigation Workflow

Validate actor → analyze timeline → assess impact → confirm intent.

## Example Detection

KQL queries detecting roleAssignments/write events.

## False Positives

Admin operations, automation scripts.

## Detection Tuning

Exclude trusted accounts and focus on high privilege roles.

## Real Attack Scenario

Phishing → Account compromise → Owner role assignment → Cloud takeover.

## SOC Analyst Responsibilities

L1 triage alerts, L2 performs deep investigation and response.

## Key Takeaways

Privilege escalation is one of the highest risk activities in cloud environments and must be monitored continuously.

---

## Connection to Previous Days

This topic builds directly on:

* Day 26 → Azure Activity Monitoring
* Day 23 → Identity & Privilege Concepts

Together they form:

```
Identity Compromise
↓
Privilege Escalation
↓
Cloud Control
↓
Persistence / Lateral Movement
```

---

## Enterprise Insight

In real SOC environments, **privilege escalation alerts are treated as HIGH or CRITICAL severity** because they often indicate:

* Active attacker presence
* Misconfigured security controls
* Potential full environment compromise

---

**This is one of the most important detection areas in cloud security. Master this well.**

