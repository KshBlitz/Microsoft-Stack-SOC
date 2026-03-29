# Day 21 – Lateral Movement Indicators

## Objective

Understand how attackers move **inside a compromised network** after initial access, and how to detect and investigate this behavior using Microsoft security tools.

This is one of the most critical SOC investigation skills because **lateral movement = confirmed attacker progression**.

---

# 1. Concept Overview

### What is Lateral Movement?

Lateral movement is when an attacker:

```
Compromised System A
↓
Uses credentials / tools
↓
Accesses System B
↓
Expands control across environment
```

It is **post-compromise activity**.

---

### Why It Matters

Initial compromise is often small.

Real damage happens when attacker:

* spreads across machines
* accesses sensitive systems
* escalates privileges
* deploys ransomware

---

### Key Insight

> If you detect lateral movement → attacker is already inside → HIGH severity

---

# 2. Why This Exists in Enterprise Security

Attackers cannot achieve goals from one machine.

They need:

* Domain Admin access
* Server access
* Data exfiltration paths

So they move laterally using:

* admin tools
* credentials
* remote execution methods

---

# 3. Architecture Context

Where lateral movement appears in Microsoft SOC:

```
Endpoint Activity
↓
Microsoft Defender for Endpoint (process + network telemetry)
↓
Log Analytics Workspace
↓
Microsoft Sentinel Analytics Rule
↓
Alert / Incident
↓
SOC Investigation
↓
ServiceNow Ticket
```

---

### Cross-System Visibility

| System                | Role                                 |
| --------------------- | ------------------------------------ |
| Defender for Endpoint | Process + remote execution telemetry |
| Microsoft Sentinel    | Detection + correlation              |
| Entra ID              | Identity + credential usage          |
| Log Analytics         | Data storage                         |

---

# 4. Core Lateral Movement Techniques

---

## 4.1 PsExec (Sysinternals Tool)

### What it does

Remote execution tool used by admins.

Attackers abuse it for:

```
Execute command on remote machine
```

---

### Behavior Pattern

```
psexec.exe
↓
Remote service creation
↓
cmd.exe / powershell.exe execution on target
```

---

### Key Indicators

* `psexec.exe` execution
* Service creation on remote system
* ADMIN$ share usage
* Remote command execution

---

---

## 4.2 WMI (Windows Management Instrumentation)

### What it does

Allows remote command execution via:

```
wmic /node:<target> process call create
```

---

### Behavior Pattern

```
wmic.exe
↓
Remote process creation
↓
powershell / cmd execution
```

---

### Why Attackers Use It

* stealthier than PsExec
* uses built-in Windows functionality
* no additional tools required

---

---

## 4.3 Remote PowerShell (WinRM)

### What it does

Execute PowerShell commands remotely.

Example:

```
Enter-PSSession
Invoke-Command
```

---

### Behavior Pattern

```
powershell.exe
↓
WinRM connection
↓
Remote script execution
```

---

### Indicators

* WinRM traffic (port 5985/5986)
* PowerShell remoting logs
* command execution on remote host

---

# 5. Log Sources / Telemetry

Key telemetry in Microsoft Defender & Sentinel:

---

### Endpoint Logs

**DeviceProcessEvents**

* Process creation
* Command line
* Parent-child relationships

---

**DeviceNetworkEvents**

* Remote connections
* SMB / WinRM traffic

---

**DeviceEvents**

* Service creation (PsExec)
* WMI activity

---

### Identity Logs

**SigninLogs / AuditLogs**

* unusual credential usage
* logins from different hosts

---

# 6. Detection Logic

---

## Detection Thinking

We detect lateral movement by identifying:

```
Remote execution + admin tools + unusual behavior
```

---

### Key Detection Patterns

---

### Pattern 1: PsExec Usage

* rare tool usage
* admin share access
* service creation

---

### Pattern 2: WMI Remote Execution

* wmic.exe spawning processes
* remote host execution

---

### Pattern 3: PowerShell Remoting

* encoded commands
* remote sessions
* suspicious scripts

---

### Pattern 4: Same Account → Multiple Hosts

```
User logs into multiple machines rapidly
```

---

# 7. Detection Example (KQL)

---

## PsExec Detection

```
DeviceProcessEvents
| where FileName =~ "psexec.exe"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

---

## WMI Remote Execution

```
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine contains "process call create"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

---

## Suspicious PowerShell Remoting

```
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "Invoke-Command"
   or ProcessCommandLine contains "Enter-PSSession"
```

---

## Lateral Movement via Account Spread

```
DeviceLogonEvents
| summarize HostCount = dcount(DeviceName) by AccountName, bin(TimeGenerated, 1h)
| where HostCount > 5
```

---

# 8. Investigation Workflow

---

## Step-by-Step SOC Investigation

---

### Step 1 – Identify Entry Point

* Which machine started activity?
* Which user account?

---

### Step 2 – Check Process Tree

```
Parent → Child relationship
```

Look for:

* psexec → cmd
* wmic → powershell
* powershell → remote execution

---

### Step 3 – Identify Target Systems

* Which machines were accessed?
* How many?

---

### Step 4 – Credential Usage

* Same account across hosts?
* Service account misuse?

---

### Step 5 – Timeline Reconstruction

```
Machine A → Machine B → Machine C
```

---

### Step 6 – Impact Analysis

* privilege escalation?
* sensitive server access?
* domain controller involvement?

---

# 9. Common Attack Scenarios

---

## Scenario 1 – Ransomware Spread

```
Initial compromise
↓
Credential theft
↓
PsExec across network
↓
Mass encryption
```

---

## Scenario 2 – Domain Takeover

```
Phishing
↓
User compromise
↓
WMI movement
↓
Domain admin access
```

---

## Scenario 3 – Living Off The Land

```
No malware
↓
PowerShell remoting
↓
Stealth lateral movement
```

---

# 10. SOC Analyst Responsibilities

---

## L1 Analyst

* Identify suspicious tool usage
* Validate alert (true vs false positive)
* Check affected systems
* Escalate if confirmed lateral movement

---

## L2 Analyst

* Deep investigation across endpoints
* correlate identity + endpoint logs
* build attack timeline
* containment recommendations

---

# 11. False Positive Considerations

---

### Legitimate Admin Activity

* IT teams use PsExec
* automation scripts
* remote management tools

---

### Indicators of Benign Activity

* known admin accounts
* expected maintenance window
* consistent usage patterns

---

# 12. Detection Tuning Strategy

---

### Reduce Noise

* exclude known admin tools usage
* whitelist service accounts
* baseline normal remote activity

---

### Improve Detection

* focus on:

  * rare usage
  * unusual accounts
  * abnormal time patterns

---

# 13. Key Terminology

* Lateral Movement
* Remote Execution
* PsExec
* WMI
* WinRM
* Credential Reuse
* Remote Service Creation
* Living-off-the-land (LOLBins)

---

# 14. Interview Talking Points

---

### Strong Answers

1. Lateral movement is post-compromise activity where attackers move across systems using tools like PsExec, WMI, and PowerShell.

2. Detection relies on identifying remote execution patterns and abnormal account behavior across multiple hosts.

3. Defender for Endpoint provides process and network telemetry used in Sentinel for detection.

4. Investigation focuses on process trees, account usage, and timeline reconstruction.

5. False positives often come from legitimate admin tools, so tuning is critical.

---

# 15. GitHub Documentation Section

---

# Day 21 – Lateral Movement Indicators

## Objective

Understand how attackers move across systems after initial compromise using tools like PsExec, WMI, and PowerShell.

## Architecture Context

Endpoint → Defender → Log Analytics → Sentinel → Incident → SOC Investigation

## Core Components

PsExec, WMI, PowerShell Remoting

## Log Sources

DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents

## Detection Logic

Detect remote execution, abnormal account usage, and multi-host access patterns.

## Investigation Workflow

Analyze process trees, track affected systems, correlate account activity, reconstruct timeline.

## Example Detection

KQL queries for PsExec, WMI, and PowerShell remoting.

## False Positives

Legitimate admin activity and automation tools.

## Detection Tuning

Exclude known admin behavior and focus on anomalies.

## Real Attack Scenario

Credential theft → lateral movement → domain compromise.

## SOC Analyst Responsibilities

L1 triage and escalation, L2 deep investigation and response.

## Key Takeaways

Lateral movement detection is critical for identifying active attackers inside the environment.

---

### Project Context Alignment

This topic directly builds on:

* Process Tree Analysis (Day 20)
* Cross-Source Correlation (Day 18)
* Defender Endpoint Telemetry (Day 19)

And prepares you for:

* Identity Investigation (Day 22)
* Privilege Escalation (Day 23)

---

This is one of the **most important SOC skills** because it transitions you from:

> alert analysis → real attack tracking

---

