# Day 18 – Correlation Across Sources (Deep Dive)

---

## Objective

Understand how enterprise SOC teams correlate telemetry across multiple data sources such as:

- SigninLogs (Identity)
- DeviceProcessEvents (Endpoint)
- OfficeActivity (Cloud / M365)

This is a **core skill for L2 analysts and detection engineers** because real attacks span **multiple systems**, not just one log source.

---

## 1. Concept Overview

**Cross-source correlation** is the process of linking events from different telemetry sources to reconstruct attacker behavior.

Instead of analyzing logs in isolation:

```
Single Log = Partial Truth
Multiple Logs Correlated = Full Attack Story
```

Example:

```
SigninLogs → Suspicious login
DeviceProcessEvents → PowerShell execution
OfficeActivity → Data access / exfiltration
```

Together → **Account compromise + endpoint execution + data impact**

---

## 2. Why This Exists in Enterprise Security

Attackers do NOT operate in one domain.

They move across:

- Identity (login compromise)
- Endpoint (execution)
- Cloud apps (data access)

Without correlation:

- Alerts look isolated
- True attack chain is missed
- Incidents are under-prioritized

Correlation solves:

- Alert fatigue
- Fragmented investigations
- Missed attack progression

---

## 3. Architecture Context

Where correlation happens in Microsoft SOC:

```
Identity Logs (Entra ID)
        ↓
Endpoint Logs (Defender for Endpoint)
        ↓
Cloud Logs (M365 / OfficeActivity)
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel (SIEM)
        ↓
Correlation Rules / KQL Queries
        ↓
Incident
        ↓
SOC Investigation
```

Key idea:

**Sentinel is the correlation engine.**

---

## 4. Core Components

### 4.1 Identity Telemetry (SigninLogs)

- User logins
- IP addresses
- Location
- Authentication result

Used for:
- Detecting compromised accounts

---

### 4.2 Endpoint Telemetry (DeviceProcessEvents)

- Process execution
- Command line
- Parent-child relationships

Used for:
- Detecting execution & persistence

---

### 4.3 Cloud Activity (OfficeActivity)

- File access
- Email activity
- SharePoint / OneDrive usage

Used for:
- Detecting data access / exfiltration

---

### 4.4 Correlation Keys

To join data across sources:

- UserPrincipalName (MOST IMPORTANT)
- IP Address
- DeviceId / Hostname
- Time window

---

## 5. Log Sources / Data Sources

| Source               | Table Name            | Purpose |
|---------------------|----------------------|--------|
| Identity            | SigninLogs           | Login tracking |
| Endpoint            | DeviceProcessEvents  | Process execution |
| Cloud (M365)        | OfficeActivity       | Data access |
| Optional            | DeviceLogonEvents    | Endpoint login |

---

## 6. Detection Logic

### Core Idea

```
Suspicious Login
+
Suspicious Process Execution
+
Sensitive Data Access
=
High Confidence Incident
```

---

### Detection Strategy

1. Detect suspicious login
2. Check if same user executed processes
3. Check if same user accessed sensitive data
4. Correlate within time window

---

### Time-Based Correlation

Typical window:

- 30 minutes
- 1 hour
- 24 hours (depending on attack)

---

## 7. Investigation Workflow

### Step 1 – Start with Alert

Example:

- Suspicious login detected

---

### Step 2 – Identity Analysis

Check:

- IP address
- Location anomaly
- Failed vs successful attempts

---

### Step 3 – Endpoint Correlation

Ask:

- Did this user execute processes?
- Any PowerShell / CMD activity?

---

### Step 4 – Cloud Activity Correlation

Check:

- File downloads
- Mailbox access
- SharePoint activity

---

### Step 5 – Timeline Reconstruction

```
Login → Execution → Data Access
```

---

### Step 6 – Decision

- Benign → Close
- Suspicious → Escalate
- Confirmed compromise → Incident response

---

## 8. Common Attack Scenario

### Scenario: Credential Theft + Data Exfiltration

```
Phishing Email
↓
User enters credentials
↓
Attacker logs in (SigninLogs)
↓
Runs PowerShell (DeviceProcessEvents)
↓
Accesses SharePoint files (OfficeActivity)
```

Without correlation → looks like 3 separate events  
With correlation → **full attack chain**

---

## 9. SOC Analyst Responsibilities

### L1 Analyst

- Review alert
- Check login details
- Validate obvious false positives
- Escalate if multi-source activity exists

---

### L2 Analyst

- Perform cross-source correlation
- Build timeline
- Write KQL queries
- Confirm compromise
- Recommend containment

---

## 10. Detection Example (KQL)

### Cross-Source Correlation Query

```
let loginEvents = SigninLogs
| where ResultType == 0
| project UserPrincipalName, IPAddress, LoginTime=TimeGenerated;

let processEvents = DeviceProcessEvents
| project DeviceName, AccountName, ProcessCommandLine, ProcessTime=TimeGenerated;

let officeEvents = OfficeActivity
| project UserId, Operation, OfficeTime=TimeGenerated;

loginEvents
| join kind=inner processEvents
    on $left.UserPrincipalName == $right.AccountName
| join kind=inner officeEvents
    on $left.UserPrincipalName == $right.UserId
| where ProcessTime between (LoginTime .. LoginTime + 1h)
| where OfficeTime between (LoginTime .. LoginTime + 1h)
| project UserPrincipalName, IPAddress, ProcessCommandLine, Operation
```

---

## 11. False Positive Considerations

Legitimate scenarios:

- User logs in and works normally
- Admin scripts triggering PowerShell
- Bulk file downloads (backup activity)

---

## 12. Tuning Strategy

To reduce noise:

- Exclude trusted IPs
- Exclude admin accounts
- Filter known scripts
- Focus on rare processes
- Add geo-anomaly filters

---

## 13. Key Terminology

- Cross-source correlation
- Entity mapping
- Timeline reconstruction
- Multi-stage attack
- Identity compromise
- Endpoint execution
- Data exfiltration
- KQL joins

---

## 14. Interview Talking Points

- Correlation across sources helps detect full attack chains instead of isolated alerts  
- Microsoft Sentinel enables correlation using KQL joins across multiple tables  
- Identity + Endpoint + Cloud logs provide complete visibility  
- Time-window correlation is critical for accurate detection  
- L2 analysts rely heavily on correlation for investigation and escalation  

---

## 15. GitHub Documentation Section

## Day 18 – Correlation Across Sources

### Objective
Understand how to correlate identity, endpoint, and cloud telemetry to detect multi-stage attacks.

### Architecture Context
Identity + Endpoint + Cloud logs flow into Log Analytics and are correlated in Microsoft Sentinel.

### Core Components
- SigninLogs
- DeviceProcessEvents
- OfficeActivity

### Log Sources
Identity, endpoint, and cloud telemetry.

### Detection Logic
Combine login + process + activity within time window.

### Investigation Workflow
Correlate logs → build timeline → determine compromise.

### Example Detection
KQL join across multiple tables.

### False Positives
Normal user activity, admin scripts.

### Detection Tuning
Exclude trusted behavior, focus on anomalies.

### Real Attack Scenario
Credential theft → PowerShell execution → data access.

### SOC Analyst Responsibilities
L1 triage, L2 deep correlation and investigation.

### Key Takeaways
Cross-source correlation is essential for detecting real enterprise attacks.

---

## Enterprise Context Reference

This topic directly aligns with the SOC learning architecture and workflow defined in the project repository, where correlation across identity, endpoint, and cloud telemetry is a core investigation capability. :contentReference[oaicite:0]{index=0}  

It is also a key milestone in the 30-day SOC engineer roadmap under **Week 3 – Sentinel Operations (Day 18)** focusing on real-world SIEM correlation. :contentReference[oaicite:1]{index=1}  

---