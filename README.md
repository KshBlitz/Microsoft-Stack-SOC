# Microsoft Enterprise SOC L1/L2 Hybrid Training Program

## Program Purpose

This 5-week structured program builds strong theoretical understanding of the Microsoft enterprise SOC ecosystem. It is designed for analysts transitioning from open-source exposure to enterprise-level Microsoft security operations.

The learning flow follows real SOC operations:

Architecture → Detection → SIEM Operations → Endpoint & Identity Investigation → Email & Cloud Monitoring → Enterprise Incident Management → Automation

By the end of this program, you should confidently explain how Microsoft Sentinel, Defender, Entra ID, Azure Activity Logs, ServiceNow, and SOAR integrate within an enterprise SOC.

---

# Week 1 – Microsoft Security Architecture and Log Pipeline

## Objective

Develop a complete mental model of how Microsoft security components interact.

## 1. Azure Tenant and Log Analytics

Understand:

- Azure tenant and subscription structure (high-level)
- Microsoft Entra ID as identity provider
- Log Analytics Workspace as centralized log storage
- Microsoft Sentinel running on top of Log Analytics
- Log tables such as SigninLogs, SecurityEvent, DeviceProcessEvents, AzureActivity

Key Concept:

Log Analytics Workspace is the data layer.  
Microsoft Sentinel is the detection and correlation layer.

---

## 2. Data Connectors and Log Flow

Understand log ingestion flow:

Log Source  
→ Data Connector  
→ Log Analytics Workspace  
→ Sentinel Analytics Rule  
→ Alert  
→ Incident  

Common connectors:

- Azure AD
- Microsoft Defender
- Office 365
- Windows Security Events
- Syslog

You must understand how logs are mapped into structured tables.

---

## 3. Component Roles

Clearly explain differences between:

- SIEM (Microsoft Sentinel)
- EDR (Defender for Endpoint)
- XDR (Microsoft 365 Defender)
- SOAR (Sentinel Playbooks)

---

## 4. Alerts and Incidents

Understand:

- Alert: Triggered by detection rule
- Incident: One or more related alerts grouped for investigation
- Severity levels
- Entity mapping (User, IP, Host)
- Why grouping reduces alert fatigue

---

## End of Week 1 Outcome

You must clearly explain the full detection pipeline:

Endpoint  
→ Defender  
→ Log Analytics  
→ Sentinel Rule  
→ Alert  
→ Incident  
→ Investigation  
→ ServiceNow Ticket  

---

# Week 2 – Kusto Query Language (KQL) for Detection Engineering

## Objective

Develop the ability to build detections using structured query logic.

---

## 1. KQL Core Structure

Understand pipeline-based querying:

Table  
| where  
| project  
| summarize  
| filter  

Master these operators:

- where
- project
- summarize
- count()
- distinct
- extend
- parse
- join
- bin()
- order by
- TimeGenerated filtering

---

## 2. Key Log Tables

Recognize purpose of:

- SigninLogs
- AuditLogs
- SecurityEvent
- DeviceProcessEvents
- DeviceEvents
- OfficeActivity
- AzureActivity

---

## 3. Detection Use Cases

Be able to write logic for:

- Brute force detection
- Multiple failed logins within time window
- Impossible travel
- Suspicious PowerShell execution
- Privileged role assignment detection
- Rare process execution

---

## 4. Detection Tuning Mindset

Understand:

- Threshold logic
- Time window logic
- Aggregation behavior
- False positive reduction

Think like an L2 analyst:

- Exclude service accounts
- Exclude trusted IP ranges
- Adjust thresholds based on risk

---

## End of Week 2 Outcome

You must be able to:

- Write structured KQL queries
- Explain detection logic clearly
- Design threshold-based detections
- Discuss tuning strategy confidently

---

# Week 3 – Microsoft Sentinel SIEM Operations

## Objective

Understand how detections are operationalized in enterprise SOC.

---

## 1. Analytics Rules

Learn:

- Scheduled rules
- Near Real-Time rules
- Query frequency vs lookback window
- Threshold configuration
- Entity mapping
- MITRE mapping
- Severity assignment

---

## 2. Detection Lifecycle

Detection Idea  
→ KQL Query  
→ Rule Creation  
→ Alert Triggered  
→ Incident Created  
→ Analyst Validation  
→ Rule Tuning  

Understand the importance of continuous improvement.

---

## 3. Incident Investigation Workflow

Learn how to:

- Use incident queue
- Filter by severity
- Open and analyze alerts
- Use investigation graph
- Review timeline
- Analyze entities
- Document findings
- Assign incidents
- Update status

Status lifecycle:

New  
In Progress  
On Hold  
Resolved  
Closed  

---

## End of Week 3 Outcome

You must be able to:

- Create analytics rules
- Explain alert grouping logic
- Investigate incidents systematically
- Document investigations properly
- Explain correlation across sources

---

# Week 4 – Endpoint and Identity Investigation

## Objective

Build investigation depth using Defender and Entra ID.

---

## 1. Microsoft Defender for Endpoint

Understand:

- Alert page structure
- Device timeline
- Process tree analysis
- Parent-child relationships
- Command-line inspection
- File hash reputation lookup
- Advanced hunting concept
- Host isolation workflow
- Execution restriction concept
- Live response concept

Be able to explain:

- Malware execution patterns
- Suspicious PowerShell activity
- Lateral movement indicators
- When to isolate a device

---

## 2. Device Timeline and Process Tree

Understand chronological reconstruction:

- Process creation
- File activity
- Network connections
- Registry modifications
- User logins

Recognize suspicious process chains and living-off-the-land techniques.

---

## 3. Identity Monitoring with Entra ID

Learn:

- Sign-in logs structure
- Audit logs
- Risky sign-ins
- Conditional Access evaluation
- Privileged role assignments
- Token misuse concept
- Impossible travel logic

Be able to explain:

- Compromised account investigation
- Privilege escalation detection
- Suspicious login patterns
- Identity and endpoint correlation

---

## End of Week 4 Outcome

You must be able to:

- Investigate endpoint alerts
- Interpret process trees
- Detect identity abuse
- Identify privilege escalation
- Correlate endpoint and identity data

---

# Week 5 – Email Security, Cloud Monitoring, Enterprise Operations and SOAR

## Objective

Complete enterprise SOC understanding beyond core SIEM.

---

## 1. Microsoft 365 Defender Email Security

Learn:

- Phishing alert workflow
- Safe Links
- Safe Attachments
- Message trace
- Email header analysis
- User-reported phishing
- Quarantine workflow

Be able to explain:

- Phishing investigation lifecycle
- Malicious attachment handling
- URL click investigation
- Campaign-wide email search
- False positive validation

---

## 2. Azure Cloud Control Plane Monitoring

Learn:

- Azure Activity Logs
- Role assignment changes
- VM creation logs
- Policy modifications
- Resource deletion logs

Understand detection of:

- Unauthorized role assignment
- Suspicious resource creation
- Cloud privilege escalation

---

## 3. ServiceNow Incident Lifecycle

Learn:

- Incident lifecycle stages
- Status transitions
- SLA timers
- Priority vs Severity
- Assignment groups
- Escalation workflow

Understand:

Severity represents technical impact.  
Priority represents business urgency.

Be able to explain how an alert becomes a ticket and how SLA compliance is maintained.

---

## 4. Sentinel Playbooks and SOAR

Learn:

- Playbook triggers
- Automation logic
- Enrichment steps
- Notification workflows
- Account disable concept
- Conditional logic in automation

Be able to explain:

- How automation reduces workload
- When automation is appropriate
- Why human validation is necessary

---

# Final Competency Outcome

After completing this program, you should confidently state:

- I understand Microsoft Sentinel architecture and log flow.
- I can write KQL queries for security detection.
- I can create and tune analytics rules.
- I can investigate incidents in Sentinel.
- I can investigate endpoint alerts in Defender.
- I understand Entra ID identity monitoring.
- I understand Azure control-plane monitoring.
- I understand ServiceNow incident lifecycle.
- I understand SOAR automation concepts.

This provides complete theoretical coverage of the Microsoft enterprise SOC stack for an L1/L2 hybrid analyst role.
