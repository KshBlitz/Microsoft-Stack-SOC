# Day 20 – Process Tree Analysis (Enterprise SOC Deep Dive)

---

# 1. Concept Overview

**Process Tree Analysis** is the investigation of **parent-child relationships between processes** on an endpoint.

Every process in an OS is **spawned by another process**, forming a **hierarchical tree**.

Example:

```
winword.exe
↓
powershell.exe
↓
malware.exe
```

This shows:

* Microsoft Word spawned PowerShell
* PowerShell executed a malicious binary

This is a **classic attack chain** used in real-world intrusions.

---

# 2. Why This Exists in Enterprise Security

Attackers rarely execute malware directly.

Instead, they:

* Abuse **trusted applications**
* Launch **living-off-the-land binaries (LOLBins)**
* Hide behind legitimate parent processes

Process tree analysis helps detect:

* Initial compromise
* Execution chains
* Privilege escalation paths
* Malware delivery techniques

Without process trees, you only see **isolated events**, not the **attack story**.

---

# 3. Architecture Context

Where process tree analysis fits:

```
Endpoint Activity
↓
Microsoft Defender for Endpoint (EDR telemetry)
↓
DeviceProcessEvents (Log Analytics)
↓
Microsoft Sentinel (SIEM detection)
↓
Alert / Incident
↓
SOC Investigation (Process Tree Analysis)
↓
Response Action
```

Key point:

* **Defender = collects process telemetry**
* **Sentinel = correlates + detects**
* **SOC Analyst = reconstructs process tree**

---

# 4. Core Components

### 4.1 Process

* Executable running on system
* Example: `powershell.exe`

### 4.2 Parent Process

* The process that launched another
* Example: `winword.exe`

### 4.3 Child Process

* Process created by parent
* Example: PowerShell spawned by Word

### 4.4 Process Tree

* Chain of execution from root to leaf

### 4.5 Command Line Arguments

Critical for detection:

```
powershell.exe -enc SQBFAFgA...
```

Shows encoded malicious payload

---

# 5. Log Sources / Data Sources

### Microsoft Defender for Endpoint

Primary table:

```
DeviceProcessEvents
```

Key fields:

* `ProcessName`
* `InitiatingProcessName`
* `ProcessCommandLine`
* `AccountName`
* `DeviceName`
* `TimeGenerated`

Other supporting tables:

* `DeviceFileEvents`
* `DeviceNetworkEvents`

---

# 6. Detection Logic

## Detection Idea

Detect suspicious parent-child relationships:

* Word → PowerShell
* Excel → CMD
* Browser → Script engine
* PowerShell → unknown executable

---

## Example Detection Logic

```
DeviceProcessEvents
| where InitiatingProcessName in ("winword.exe","excel.exe","outlook.exe")
| where ProcessName in ("powershell.exe","cmd.exe")
| project TimeGenerated, DeviceName, AccountName, 
          InitiatingProcessName, ProcessName, ProcessCommandLine
```

---

## Behavioral Detection

Instead of static rules:

* Rare parent-child relationships
* Encoded commands
* Suspicious execution paths

---

## Threshold Logic

* Multiple suspicious executions within time window
* Same user triggering repeated chains

---

## Correlation Logic

Combine:

```
Process Events
+
File Creation
+
Network Connection
```

To confirm full attack chain

---

# 7. Investigation Workflow (SOC Analyst Thinking)

## Step 1 – Start from Alert

Alert:

> Suspicious PowerShell execution from Word

---

## Step 2 – Identify Parent Process

* Was it:

  * winword.exe?
  * outlook.exe?

Check legitimacy:

* Was a document opened?
* Was it downloaded?

---

## Step 3 – Analyze Command Line

Look for:

* Encoded commands (`-enc`)
* Download cradles
* Execution policies bypass

---

## Step 4 – Expand Process Tree

Build full chain:

```
explorer.exe
↓
winword.exe
↓
powershell.exe
↓
malware.exe
```

---

## Step 5 – Check Child Actions

* Did PowerShell:

  * Download file?
  * Create executable?
  * Spawn new process?

---

## Step 6 – Correlate with Other Logs

* File creation → `DeviceFileEvents`
* Network calls → `DeviceNetworkEvents`
* Login activity → `SigninLogs`

---

## Step 7 – Determine Impact

Questions:

* Was malware executed?
* Did persistence occur?
* Was lateral movement initiated?

---

## Step 8 – Verdict

* False Positive
* Suspicious
* Confirmed compromise

---

# 8. Common Attack Scenarios

## 8.1 Phishing → Macro Execution

```
Email Attachment
↓
winword.exe
↓
powershell.exe
↓
payload download
```

---

## 8.2 Living-off-the-Land Attack

```
explorer.exe
↓
cmd.exe
↓
powershell.exe
↓
credential dump
```

---

## 8.3 Malware Execution Chain

```
browser.exe
↓
downloaded.exe
↓
malware.exe
```

---

## 8.4 Fileless Attack

```
winword.exe
↓
powershell.exe (encoded)
↓
memory execution
```

---

# 9. SOC Analyst Responsibilities

## L1 Analyst

* Review alert
* Validate process chain
* Identify suspicious relationships
* Escalate if needed

---

## L2 Analyst

* Deep process tree reconstruction
* Correlate multi-source telemetry
* Perform threat validation
* Tune detection rules

---

# 10. Detection Example (Advanced)

### Rare Parent-Child Detection

```
DeviceProcessEvents
| summarize count() by InitiatingProcessName, ProcessName
| where count_ < 5
```

Detects unusual execution relationships

---

### Encoded PowerShell Detection

```
DeviceProcessEvents
| where ProcessName == "powershell.exe"
| where ProcessCommandLine contains "-enc"
```

---

# 11. False Positive Considerations

Legitimate scenarios:

* IT automation scripts
* Admin tools using PowerShell
* Software updates
* Office plugins

---

# 12. Tuning Strategy

Reduce noise by:

* Excluding known admin accounts
* Allowlisting trusted scripts
* Filtering known parent-child pairs
* Adding environment-specific baselines

---

# 13. Key Terminology

* Process Tree
* Parent Process
* Child Process
* Command Line Analysis
* Living-off-the-Land (LOLBins)
* EDR Telemetry
* Behavioral Detection
* Execution Chain

---

# 14. Interview Talking Points

1. Process tree analysis helps reconstruct attacker behavior using parent-child relationships
2. It is critical in detecting fileless and living-off-the-land attacks
3. Defender for Endpoint provides process telemetry via DeviceProcessEvents
4. Suspicious chains like Word → PowerShell are strong attack indicators
5. Investigation involves expanding the full execution chain and correlating logs

---

# 15. GitHub Documentation Section

## Objective

Understand how process trees help detect and investigate endpoint attacks.

---

## Architecture Context

Endpoint → Defender → Log Analytics → Sentinel → Incident → SOC Investigation

---

## Core Components

* Process
* Parent Process
* Child Process
* Command Line

---

## Log Sources

* DeviceProcessEvents
* DeviceFileEvents
* DeviceNetworkEvents

---

## Detection Logic

Detect suspicious parent-child relationships and encoded commands.

---

## Investigation Workflow

* Identify parent process
* Analyze command line
* Expand process tree
* Correlate logs
* Determine impact

---

## Example Detection

Word spawning PowerShell detection using KQL

---

## False Positives

Admin scripts, automation tools

---

## Detection Tuning

Allowlisting + baseline behavior

---

## Real Attack Scenario

Phishing → Word → PowerShell → Malware

---

## SOC Analyst Responsibilities

* L1: triage and validation
* L2: deep investigation and tuning

---

## Key Takeaways

* Process trees reveal attack chains
* Parent-child relationships are critical signals
* Endpoint telemetry is the foundation of investigation
* Correlation is required for confirmation

---

# Visual Understanding (Add to GitHub)

## Process Tree Example

![Image](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AASeSXACVc8wDiLGoUpTpYQ.jpeg)

![Image](https://miro.medium.com/1%2AIs82Z2FHqlDKCfm4cnHZKg.png)

![Image](https://help.comodo.com/uploads/Comodo%20EDR/f5ac9acc337a0e8aea19781f31b0fad5/5eac818f1e1c4adc19d335055b06586b/bde05c108a514f9867fcc90edf0718e3/edr_pt5.png)

![Image](https://www.ibm.com/support/pages/system/files/inline-images/image-20230530155939-1.png)

---

## Word → PowerShell Attack Chain

![Image](https://www.fortinet.com/it/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain/_jcr_content/root/responsivegrid/table_content/par/image_1234039696.img.jpeg/1765214893937/fig01-clickfix-powershell-campaign.jpeg)

![Image](https://learn.microsoft.com/en-us/microsoft-365-apps/security/media/internet-macros-blocked/vba-macro-flowchart.png)

![Image](https://miro.medium.com/0%2A3eHxUSj5STnl9chk)

![Image](https://www.cyfirma.com/media/2025/01/living04-1.jpg)

---

# Enterprise Context Reminder

This topic directly supports:

* Detection Engineering
* Incident Investigation
* Endpoint Detection and Response (EDR)
* Microsoft Sentinel SIEM Operations

It is one of the **most critical skills in SOC investigations**.

---

# Project Context Reference

This content aligns with the enterprise SOC learning architecture and workflow defined in your project  and follows the structured 30-day roadmap for building SOC expertise  while adhering to real-world SOC training principles .

---

# Final Insight

If you master process tree analysis, you move from:

**"seeing alerts" → to → "understanding attacker behavior"**

That is the difference between:

* Tool operator
  vs
* Real SOC analyst

---
