# Day 19 – Microsoft Defender for Endpoint (Deep Dive)

## Objective

Understand how **Microsoft Defender for Endpoint (MDE)** is used in enterprise SOC operations for:

* Device-level investigation
* Alert analysis
* File-based threat validation

Focus areas:

* Device Timeline
* Alert Page
* File Hash Lookup

---

# 1. Concept Overview

Microsoft Defender for Endpoint is an **Endpoint Detection and Response (EDR)** platform that provides:

* Real-time endpoint telemetry
* Behavioral detection of threats
* Deep investigation capabilities

It enables SOC analysts to:

* Reconstruct attack timelines
* Analyze suspicious processes
* Validate malicious files

---

# 2. Why This Exists in Enterprise Security

Traditional antivirus is not enough.

Modern attacks:

* Fileless malware
* Living-off-the-land attacks
* Script-based execution

MDE solves this by:

* Capturing **behavioral telemetry**
* Providing **deep visibility into endpoint activity**
* Enabling **post-breach investigation**

---

# 3. Architecture Context

MDE sits at the **endpoint layer** of the Microsoft security ecosystem.

```
Endpoint Activity
↓
Microsoft Defender for Endpoint (EDR Telemetry)
↓
Microsoft 365 Defender (XDR Correlation)
↓
Log Analytics Workspace
↓
Microsoft Sentinel (SIEM)
↓
Alert → Incident
↓
SOC Investigation
↓
ServiceNow Ticket
```

This is part of the enterprise SOC pipeline described in your project 

---

# 4. Core Components

## 4.1 Device Timeline

A **chronological view of all activity on a device**

Includes:

* Process execution
* File creation/modification
* Network connections
* Registry changes
* Logins

---

## 4.2 Alert Page

Detailed view of a triggered detection

Includes:

* Alert description
* Severity
* MITRE mapping
* Affected device/user
* Evidence (files, processes, IPs)

---

## 4.3 File Hash Lookup

Used to validate suspicious files

Hash types:

* MD5
* SHA1
* SHA256

Used for:

* Malware validation
* Threat intelligence enrichment
* Cross-device correlation

---

# 5. Log Sources / Data Sources

Key MDE telemetry tables:

* `DeviceProcessEvents`
* `DeviceFileEvents`
* `DeviceNetworkEvents`
* `DeviceRegistryEvents`
* `DeviceLogonEvents`

These logs are also used in Sentinel detection engineering (Week 2 → Week 3 progression )

---

# 6. Detection Logic

## Detection happens in two ways:

### 1. Built-in Defender Detections

* Behavioral analytics
* Machine learning
* Threat intelligence

### 2. Custom KQL Detections (Sentinel)

Example logic:

* Suspicious process execution
* Rare file activity
* Unusual parent-child process chains

---

## Detection Example Logic

**Suspicious PowerShell execution**

```
DeviceProcessEvents
| where ProcessName == "powershell.exe"
| where ProcessCommandLine contains "EncodedCommand"
```

---

# 7. Investigation Workflow

## Full SOC Investigation Flow

```
Alert Triggered
↓
Open Alert Page
↓
Identify Device + User
↓
Open Device Timeline
↓
Reconstruct Attack Sequence
↓
Identify Suspicious Process/File
↓
Perform File Hash Lookup
↓
Check Threat Intelligence
↓
Decide: True Positive / False Positive
↓
Escalate or Close
```

---

## Step-by-Step Thinking

### Step 1 – Start from Alert

* What triggered this alert?
* Which device is impacted?

---

### Step 2 – Analyze Alert Page

* Detection type
* Severity
* Related entities

---

### Step 3 – Move to Device Timeline

* What happened before and after?
* Identify:

  * Initial execution
  * Persistence attempts
  * Lateral movement

---

### Step 4 – Investigate File

* Extract file hash
* Check:

  * Known malware?
  * Seen on other devices?

---

### Step 5 – Decision

* Malicious → escalate
* Benign → close + tune

---

# 8. Device Timeline (Deep Understanding)

## What It Really Is

A **forensic reconstruction tool**

Instead of raw logs, it gives:

* Sequenced activity
* Visual correlation

---

## Example Timeline

```
User Login
↓
Word.exe opened
↓
Macro executed
↓
powershell.exe spawned
↓
Encoded command executed
↓
Suspicious file dropped
↓
External IP connection
```

---

## Why It’s Critical

Without timeline:

* Logs are disconnected

With timeline:

* You see the **attack story**

---

# 9. Alert Page (Deep Understanding)

## What It Shows

* Detection rule triggered
* Context of attack
* Evidence collected

---

## Key Sections

### 1. Alert Summary

* What happened

### 2. Entities

* User
* Device
* IP
* File

### 3. Evidence

* Process
* File hash
* Network indicators

---

## SOC Insight

Alert page = **entry point**
Timeline = **deep investigation**

---

# 10. File Hash Lookup (Deep Understanding)

## Why Hash Matters

File name can change
Hash cannot (for same file)

---

## Use Cases

* Malware identification
* Threat intelligence lookup
* Cross-environment detection

---

## Investigation Questions

* Is this hash known malware?
* Seen in threat intel feeds?
* Seen on multiple devices?

---

## Example Workflow

```
Suspicious File Detected
↓
Extract SHA256
↓
Search in Defender
↓
Check global prevalence
↓
Check threat intelligence
↓
Decide malicious/benign
```

---

# 11. Common Attack Scenarios

## 1. Phishing → Malware Execution

```
Email Attachment
↓
User opens file
↓
Macro runs
↓
PowerShell executes
↓
Malware dropped
```

---

## 2. Living-off-the-Land Attack

```
cmd.exe
↓
powershell.exe
↓
Encoded commands
↓
No file dropped
```

---

## 3. Lateral Movement

```
Compromised Host
↓
Remote execution
↓
New device timeline activity
```

---

# 12. SOC Analyst Responsibilities

## L1 Analyst

* Review alert page
* Identify affected device/user
* Perform basic timeline review
* Check file hash reputation
* Escalate if suspicious

---

## L2 Analyst

* Deep timeline reconstruction
* Cross-device correlation
* Advanced KQL queries
* Detection tuning
* Incident scoping

---

# 13. False Positive Considerations

## Common Benign Cases

* Admin scripts using PowerShell
* Software updates
* IT automation tools
* Security tools executing commands

---

## Example

PowerShell with encoded command ≠ always malicious

---

# 14. Detection Tuning Strategy

* Exclude known admin tools
* Exclude trusted scripts
* Baseline normal process behavior
* Reduce noise from IT operations

---

# 15. Key Terminology

* EDR (Endpoint Detection & Response)
* Device Timeline
* Alert Evidence
* File Hash (SHA256)
* Process Tree
* Threat Intelligence
* Behavioral Detection
* Endpoint Telemetry

---

# 16. Interview Talking Points

1. Defender for Endpoint provides **deep endpoint visibility using behavioral telemetry**, not just signatures.

2. Device timeline is used to **reconstruct attack sequences step-by-step**, which is critical for incident investigation.

3. Alert page gives **context and evidence**, but timeline provides **full attack story**.

4. File hash lookup is essential for **malware validation and threat intelligence correlation**.

5. SOC analysts use MDE to **detect, investigate, and validate endpoint threats before escalating incidents**.

---

# 17. Real Attack Walkthrough (Full SOC Thinking)

```
Alert: Suspicious PowerShell Execution
↓
Alert Page → powershell.exe with encoded command
↓
Device Timeline →
    Word.exe → powershell.exe → file drop
↓
File Hash Extracted
↓
Hash lookup → Known malware
↓
Check spread → 3 devices affected
↓
Conclusion → True Positive
↓
Escalate to Incident Response
```

---

# 18. GitHub Documentation Section

## Day 19 – Defender for Endpoint

### Objective

Learn how endpoint telemetry is used for detection and investigation in enterprise SOC.

### Key Components

* Device Timeline
* Alert Page
* File Hash Lookup

### Investigation Flow

Alert → Timeline → File Analysis → Decision

### Detection Use Cases

* PowerShell abuse
* Malware execution
* Lateral movement

### SOC Value

Defender enables **deep endpoint visibility and attack reconstruction**, making it a core tool in SOC investigations.

---

# 19. Key Takeaways

* Defender for Endpoint is the **primary investigation tool for endpoint threats**
* Device timeline = **attack reconstruction**
* Alert page = **starting point**
* File hash = **malware validation**
* SOC workflow depends heavily on **correlating these three together**

---

# FINAL CONNECTION TO YOUR SOC LEARNING PATH

This day connects directly to:

* Day 17 → Investigation Graph (entity relationships)
* Day 18 → Cross-source correlation
* Day 20 → Process Tree Analysis (next step)

You are now moving from:
**SIEM-level investigation → Endpoint-level deep forensics**

This is where real SOC analysts become dangerous (in a good way).

---
