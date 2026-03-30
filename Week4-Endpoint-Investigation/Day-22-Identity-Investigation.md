# Day 22 – Identity Investigation (SigninLogs & AuditLogs)

## Objective

Understand how identity-based attacks are detected and investigated using **Microsoft Entra ID telemetry**, focusing on:

* Sign-in behavior analysis
* Impossible travel detection
* Token abuse detection
* Audit trail analysis

This is one of the **most critical SOC skills**, because identity is the primary attack surface in modern enterprises.

---

# 1. Concept Overview

Identity investigation focuses on analyzing **authentication and account activity** to detect compromise.

Key idea:

```
User Identity
↓
Authentication Events (SigninLogs)
↓
Directory Changes (AuditLogs)
↓
Suspicious Behavior Detection
↓
SOC Investigation
```

Two main log sources:

### SigninLogs

* Authentication attempts
* Success / failure
* IP address
* Location
* Device info
* Authentication method

### AuditLogs

* Changes in identity environment
* Role assignments
* MFA changes
* Application consent
* Token-related actions

---

# 2. Why This Exists in Enterprise Security

Modern attacks target **credentials instead of systems**.

Attackers prefer:

* Password spraying
* Phishing
* Token theft
* Session hijacking

Because:

* No malware needed
* Harder to detect
* Looks like normal user activity

Identity monitoring exists to:

* Detect account compromise
* Detect abnormal login patterns
* Track privilege abuse
* Monitor identity configuration changes

---

# 3. Architecture Context

Where identity logs fit:

```
User Login Attempt
↓
Microsoft Entra ID
↓
SigninLogs / AuditLogs
↓
Log Analytics Workspace
↓
Microsoft Sentinel (SIEM)
↓
Analytics Rule
↓
Alert → Incident
↓
SOC Investigation
```

This connects directly to the enterprise SOC pipeline 

---

# 4. Core Components

### Identity Signals

* UserPrincipalName
* IP Address
* Location (Country/City)
* Device ID
* Authentication method
* Risk level

---

### Authentication Types

* Interactive login
* Non-interactive login (tokens, apps)
* Service principal authentication

---

### Risk Indicators

* Impossible travel
* Anonymous IP usage
* Unfamiliar sign-in properties
* Token anomalies

---

# 5. Log Sources / Data Sources

### SigninLogs

Important fields:

* TimeGenerated
* UserPrincipalName
* IPAddress
* Location
* ResultType
* AppDisplayName
* ConditionalAccessStatus
* RiskLevelDuringSignIn

---

### AuditLogs

Important fields:

* ActivityDisplayName
* InitiatedBy
* TargetResources
* ModifiedProperties
* Result

---

# 6. Detection Logic

---

## A. Impossible Travel Detection

### Concept

Same user logs in from **two distant locations in short time**

Example:

* Login from India
* 10 minutes later → login from USA

Impossible physically → likely compromise

---

### Detection Logic

* Same user
* Different geolocations
* Short time window

---

### KQL Example

```
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0
| project UserPrincipalName, TimeGenerated, IPAddress, Location
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend prevTime = prev(TimeGenerated), prevLocation = prev(Location)
| where UserPrincipalName == prev(UserPrincipalName)
| where Location != prevLocation
| where datetime_diff("minute", TimeGenerated, prevTime) < 60
```

---

## B. Token Abuse Detection

### Concept

Attackers steal **authentication tokens** to bypass credentials.

Token abuse includes:

* Reuse of refresh tokens
* Access from multiple IPs using same session
* Non-interactive suspicious access

---

### Detection Logic

* Non-interactive sign-ins
* Multiple IPs for same session
* Unusual application usage

---

### KQL Example

```
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where ClientAppUsed != "Browser"
| summarize IPCount = dcount(IPAddress) by UserPrincipalName, AppDisplayName
| where IPCount > 3
```

---

## C. Suspicious Audit Activity

### Example detections

* MFA disabled
* New global admin assigned
* App consent granted

---

### KQL Example

```
AuditLogs
| where ActivityDisplayName in ("Add member to role", "Update user", "Consent to application")
| project TimeGenerated, InitiatedBy, ActivityDisplayName, TargetResources
```

---

# 7. Investigation Workflow

---

## Step-by-Step Identity Investigation

### Step 1 – Identify the User

* Who logged in?
* Is it a privileged account?

---

### Step 2 – Analyze Login Pattern

From SigninLogs:

* IP addresses
* Locations
* Time pattern
* Device info

---

### Step 3 – Look for Anomalies

* Impossible travel
* New country
* TOR / VPN usage
* Failed → success sequence

---

### Step 4 – Check Token Behavior

* Non-interactive logins
* Multiple IP usage
* API/application access

---

### Step 5 – Review Audit Logs

* Role changes
* MFA changes
* App registrations

---

### Step 6 – Correlate with Other Logs

```
SigninLogs
+
DeviceLogs
+
OfficeActivity
```

Look for:

* Email access
* File downloads
* Endpoint activity

---

### Step 7 – Determine Impact

* Data accessed?
* Privileges escalated?
* Lateral movement initiated?

---

# 8. Common Attack Scenarios

---

## 1. Phishing → Account Compromise

```
User enters credentials
↓
Attacker logs in
↓
Suspicious location detected
↓
Mailbox access
```

---

## 2. Token Theft

```
Attacker steals session token
↓
Access without password
↓
Multiple IP usage
```

---

## 3. Privilege Escalation

```
Compromised account
↓
Adds Global Admin role
↓
Full tenant control
```

---

## 4. OAuth Abuse

```
User consents malicious app
↓
App gains mailbox access
↓
Persistent access
```

---

# 9. SOC Analyst Responsibilities

---

## L1 Analyst

* Review sign-in alerts
* Validate location anomalies
* Check IP reputation
* Identify obvious compromise
* Escalate if suspicious

---

## L2 Analyst

* Deep investigation across logs
* Correlate identity + endpoint
* Analyze token usage
* Validate persistence mechanisms
* Recommend containment

---

# 10. Detection Example (Combined)

```
SigninLogs
| where ResultType == 0
| summarize Locations = make_set(Location), IPs = make_set(IPAddress) by UserPrincipalName
| where array_length(Locations) > 2 and array_length(IPs) > 3
```

---

# 11. False Positive Considerations

Common benign cases:

* VPN usage
* Traveling users
* Corporate proxy IPs
* Cloud apps using multiple regions
* Mobile network IP switching

---

# 12. Tuning Strategy

Reduce noise by:

* Excluding trusted IP ranges
* Excluding service accounts
* Filtering known VPN gateways
* Increasing threshold for IP count
* Using Conditional Access signals

---

# 13. Key Terminology

* SigninLogs
* AuditLogs
* Impossible Travel
* Token Abuse
* Non-interactive Sign-in
* Conditional Access
* OAuth Consent
* Identity Risk
* Session Token
* Privileged Account

---

# 14. Interview Talking Points

* Identity is the **primary attack surface in modern SOC environments**
* SigninLogs help detect **authentication anomalies**
* AuditLogs track **configuration and privilege changes**
* Impossible travel indicates **likely credential compromise**
* Token abuse allows attackers to **bypass MFA and passwords**

---

# 15. GitHub Documentation Section

## Day 22 – Identity Investigation

### Objective

Understand detection and investigation of identity-based attacks using SigninLogs and AuditLogs.

---

### Architecture Context

```
User Login
↓
Entra ID Logs
↓
Log Analytics
↓
Microsoft Sentinel
↓
Incident
↓
SOC Investigation
```

---

### Log Sources

* SigninLogs → authentication activity
* AuditLogs → identity changes

---

### Detection Logic

* Impossible travel
* Token abuse
* Privilege changes

---

### Investigation Workflow

* Analyze login patterns
* Validate anomalies
* Correlate logs
* Assess impact

---

### Example Detection

Impossible travel query using SigninLogs

---

### False Positives

* VPN users
* Travel activity
* Proxy infrastructure

---

### Key Takeaways

* Identity attacks are stealthy and high-impact
* Correlation across logs is critical
* Token abuse is harder to detect than passwords
* Audit logs reveal persistence and privilege abuse

---

# Final Note

This day connects directly with:

* Detection engineering (Week 2)
* Correlation (Day 18)
* Lateral movement (Day 21)

Because identity compromise is often the **starting point of full enterprise breach chains** 

And mastering this is essential to think like a real SOC analyst 
