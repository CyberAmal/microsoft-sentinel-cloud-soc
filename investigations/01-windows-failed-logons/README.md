# Investigation 01 — Repeated Windows Failed Logons

**Project:** Microsoft Sentinel Cloud SOC & Threat Detection  
**Endpoint:** Thor (Windows 11)  
**Severity:** Medium  
**MITRE ATT&CK:** T1110 — Brute Force

## Overview

Investigated repeated Windows authentication failures using Microsoft Sentinel. A controlled test involving incorrect SSH passwords was performed against the Windows 11 endpoint `Thor`.

Windows Security Event 4625 was collected through Azure Monitor Agent and analysed using a scheduled Microsoft Sentinel detection rule.

## Lab Architecture

```mermaid
flowchart LR
    A["Windows 11 — Thor"] --> B["Windows Security Event Logs"]
    B --> C["Azure Monitor Agent"]
    C --> D["Log Analytics"]
    D --> E["Microsoft Sentinel"]
    E --> F["Alert and Incident"]
```

## 1. Windows Event Log Analysis

**Event ID:** 4625 - An account failed to log on.

**KQL investigation query:**

```kusto
Event
| where TimeGenerated > ago(1h)
| where EventID == 4625
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
```

Six failed authentication events were recorded on `Thor` within approximately seven seconds.

![Failed Logon Events](screenshots/01-failed-logons-kql.png)

## 2. Microsoft Sentinel Detection

**Analytics rule:** `Repeated Windows Failed Logons`

**KQL detection rule:**

```kusto
Event
| where TimeGenerated > ago(10m)
| where EventID == 4625
| summarize FailedAttempts = count(),
            FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated)
    by Computer
| where FailedAttempts >= 5
| project LastAttempt, Computer, FailedAttempts, FirstAttempt
```

| Setting | Configuration |
|---|---|
| Rule type | Scheduled |
| Frequency | Every 5 minutes |
| Lookback | 10 minutes |
| Detection threshold | 5 or more failed logons |
| Alert trigger | Query results greater than 0 |
| Entity mapping | HostName → Computer |
| Severity | Medium |

The rule counts failures by endpoint, rather than by username or source IP.

![Sentinel Analytics Rule](screenshots/02-analytics-rule.png)

## 3. Alert and Incident Investigation

Microsoft Sentinel generated a medium-severity security alert after detecting six failed authentication attempts.

![Sentinel Security Alert](screenshots/03-sentinel-alert.png)

**Selected incident:** 31

| Field | Finding |
|---|---|
| Severity | Medium |
| Status | Active |
| Classification | Unclassified |
| Associated alerts | 11 |
| Affected endpoint | Thor |
| Detection source | Microsoft Sentinel |

![Sentinel Incident](screenshots/04-sentinel-incident.png)

The incident's Assets tab confirmed `Thor` as the affected device.

![Affected Assets](screenshots/05-incident-assets.png)

## 4. Detection Workflow

```mermaid
flowchart TD
    A["Controlled Failed Logon Attempts"] --> B["Windows Event 4625"]
    B --> C["Azure Log Analytics"]
    C --> D["Sentinel KQL Detection"]
    D --> E{"5+ Failures in 10 Minutes?"}
    E -->|Yes| F["Medium-Severity Alert"]
    F --> G["Incident 31"]
    G --> H["SOC Investigation"]
```

## 5. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated authentication failures can indicate password-guessing activity |

## 6. Findings and Outcome

- Confirmed collection of Windows Security Event 4625.
- Identified six failed authentication attempts on `Thor`.
- Validated the Microsoft Sentinel detection threshold.
- Confirmed medium-severity alert generation.
- Investigated Incident 31 and verified the affected endpoint.
- Confirmed the activity originated from an authorised lab simulation.

**Outcome:** Detection successfully validated. No confirmed malicious compromise.

## Skills Demonstrated

Windows Event Log Analysis · Microsoft Sentinel · KQL · Failed Logon Detection · Incident Triage · MITRE ATT&CK
