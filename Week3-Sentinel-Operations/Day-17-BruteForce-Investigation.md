# Day 17 – Investigation Graph
## Focus: Entity Relationships + Timeline Reconstruction

---

# 1. Concept Overview

An **Investigation Graph** is a visual and logical representation of how different security entities are connected during an incident.

It answers:

- What happened?
- Who did it?
- From where?
- On which system?
- What was the sequence of events?

Instead of looking at logs individually, the investigation graph connects:

```
User ↔ IP ↔ Device ↔ Process ↔ File ↔ Alert
```

This allows analysts to understand the **full attack story instead of isolated alerts**.

---

# 2. Why This Exists in Enterprise Security

Modern attacks are **multi-stage and distributed**:

```
Phishing → Credential Theft → Login → PowerShell → Lateral Movement
```

Problems without graph-based investigation:

- Alerts appear disconnected
- Analysts miss relationships
- Hard to identify attack scope
- Slow investigations

Investigation graphs solve this by:

- Linking related activities
- Showing attack progression
- Reducing investigation time
- Improving detection accuracy

---

# 3. Architecture Context (Microsoft SOC)

```
Endpoint Activity / Identity Logs / Cloud Logs
↓
Microsoft Defender (EDR/XDR)
↓
Log Analytics Workspace
↓
Microsoft Sentinel
↓
Incident (Entity Mapping)
↓
Investigation Graph
↓
SOC Investigation
```

From your SOC pipeline :contentReference[oaicite:0]{index=0}:

```
Alert → Incident → SOC Investigation
```

The **Investigation Graph is part of the SOC Investigation phase**.

---

# 4. Core Components of Investigation Graph

### 1. Entities

Entities are the building blocks:

- User (UPN)
- IP Address
- Device (hostname)
- Process
- File (hash)
- URL / Domain

---

### 2. Relationships

Defines how entities connect:

- User logged in from IP
- IP accessed device
- Device executed process
- Process created file

---

### 3. Timeline

Events arranged chronologically:

```
Time → Sequence → Behavior Pattern
```

---

### 4. Alerts & Incidents

- Alerts provide detection signals
- Incidents group alerts
- Graph connects all entities inside incident

---

# 5. Log Sources / Data Sources

Investigation graphs rely on multiple telemetry sources:

### Identity Logs
- `SigninLogs`
- `AuditLogs`

### Endpoint Logs
- `DeviceProcessEvents`
- `DeviceLogonEvents`
- `DeviceFileEvents`

### Cloud Logs
- `AzureActivity`

### Email Logs
- `OfficeActivity`

---

# 6. Detection Logic Behind Graph Creation

Investigation graphs depend on **entity mapping inside detection rules**.

### Example Mapping

| Field | Entity |
|------|--------|
| UserPrincipalName | User |
| IPAddress | IP |
| DeviceName | Host |

---

### Example Detection Query

```
SigninLogs
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName
```

This feeds:

```
User ↔ IP ↔ Application
```

Graph builds automatically when alerts share entities.

---

# 7. Investigation Workflow (SOC Analyst Thinking)

## Step 1 – Start from Incident

- Open incident in Sentinel
- Identify involved entities

---

## Step 2 – Identify Primary Entity

Start with:

- User (compromise?)
- Device (infected?)
- IP (attacker source?)

---

## Step 3 – Expand Relationships

Ask:

- What IP did user use?
- What device was accessed?
- What processes were executed?

---

## Step 4 – Build Timeline

```
Login Event
↓
Suspicious Process
↓
File Drop
↓
Network Connection
```

---

## Step 5 – Validate Behavior

Check:

- Is activity normal?
- Is location unusual?
- Is process suspicious?

---

## Step 6 – Determine Scope

- Single device?
- Multiple users?
- Lateral movement?

---

## Step 7 – Conclude

- False Positive
- Suspicious
- Confirmed Attack

---

# 8. Timeline Reconstruction (Core Skill)

Timeline reconstruction = **rebuilding the attack sequence**

### Example

```
10:01 → Failed logins
10:05 → Successful login
10:07 → PowerShell execution
10:10 → New admin account created
```

This shows:

- Brute force → Access → Exploitation → Privilege escalation

---

### KQL Example for Timeline

```
union SigninLogs, DeviceProcessEvents
| where TimeGenerated between (ago(1d) .. now())
| sort by TimeGenerated asc
```

---

# 9. Common Attack Scenarios Using Graphs

### 1. Brute Force Attack

```
Multiple failed logins → Success → Suspicious activity
```

---

### 2. Phishing Attack

```
Email → Credential theft → Login → Data access
```

---

### 3. Malware Execution

```
User → Email attachment → Process → File → Network call
```

---

### 4. Lateral Movement

```
User → Device A → Remote login → Device B
```

---

# 10. SOC Analyst Responsibilities

## L1 Analyst

- Identify key entities
- Perform initial graph expansion
- Check obvious malicious indicators
- Escalate if needed

---

## L2 Analyst

- Deep relationship analysis
- Timeline reconstruction
- Cross-source correlation
- Detection tuning based on findings

---

# 11. False Positive Considerations

Legitimate scenarios:

- User traveling (new IP)
- Admin running scripts
- Scheduled automation tasks
- VPN usage

---

# 12. Detection Tuning Strategy

To improve graph quality:

- Ensure correct entity mapping
- Remove noisy entities (service accounts)
- Exclude trusted IP ranges
- Adjust detection thresholds

---

# 13. Key Terminology

- Entity Mapping
- Investigation Graph
- Timeline Reconstruction
- Alert Correlation
- Incident Context
- Security Telemetry
- Behavioral Analysis
- Attack Chain

---

# 14. Interview Talking Points

1. Investigation graph helps correlate entities like user, IP, and device to understand attack flow.
2. It enables timeline reconstruction, which is critical for identifying attack progression.
3. It reduces investigation time by visually linking related alerts and activities.
4. Entity mapping in detection rules is essential for building accurate graphs.
5. SOC analysts use graphs to determine attack scope and impact.

---

# 15. GitHub Documentation Section

## Objective

Understand how investigation graphs help correlate entities and reconstruct attack timelines in enterprise SOC operations.

---

## Architecture Context

```
Logs → Sentinel → Incident → Investigation Graph → SOC Analysis
```

---

## Core Components

- Entities (User, IP, Device)
- Relationships
- Timeline
- Alerts/Incidents

---

## Log Sources

- SigninLogs
- DeviceProcessEvents
- AzureActivity
- OfficeActivity

---

## Detection Logic

Entity mapping enables correlation across alerts.

---

## Investigation Workflow

1. Start from incident  
2. Identify entities  
3. Expand relationships  
4. Build timeline  
5. Validate activity  

---

## Example Detection

```
SigninLogs
| where ResultType == 0
```

---

## False Positives

- VPN usage
- Admin scripts
- Automation accounts

---

## Detection Tuning

- Exclude trusted entities
- Improve mapping
- Reduce noise

---

## Real Attack Scenario

```
Phishing → Login → PowerShell → Lateral Movement
```

---

## SOC Responsibilities

- L1: triage + basic analysis  
- L2: deep investigation + correlation  

---

## Key Takeaways

- Investigation graph connects entities across logs  
- Timeline reconstruction reveals attack sequence  
- Critical for real SOC incident investigation  

---

# Connection to Your SOC Learning Path

From your roadmap :contentReference[oaicite:1]{index=1}:

- Day 15 → Alert Triage  
- Day 16 → Incident Queue  
- **Day 17 → Investigation Graph (THIS)**
- Day 18 → Cross-Source Correlation  

This day is the **bridge between triage and deep investigation**.

Without mastering this:

- You cannot understand attack flow
- You cannot correlate alerts
- You cannot perform real SOC investigations

---

# Final Mental Model

Think like this:

```
Logs → Signals → Entities → Relationships → Timeline → Story → Decision
```

That “story” is what separates:

- Beginner SOC analyst ❌  
- Real enterprise investigator ✅