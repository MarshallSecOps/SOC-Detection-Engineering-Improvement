# PowerShell Execution - False Positive Analysis

## Overview

This document provides detailed analysis of common false positive scenarios for PowerShell execution alerts, including root causes, identification methods, and remediation strategies. Understanding these patterns is critical for effective alert tuning and analyst efficiency.

**Key Insight:** 90-95% of baseline PowerShell alerts in enterprise environments are false positives. Most stem from legitimate automation, system maintenance, and administrative tasks that share characteristics with attacker tradecraft.

---

## False Positive Categories

### 1. Enterprise Management & Deployment Tools

**Frequency:** Very High (40-50% of all FPs)

**Common Sources:**
- SCCM (System Center Configuration Manager)
- Group Policy Objects (GPO)
- Intune / Microsoft Endpoint Manager
- Third-party patch management (WSUS, Ivanti, ManageEngine)

---

#### FP Scenario 1: SCCM Software Deployment

**Example Event:**
```
Time: 2024-01-15 02:15:33
User: NT AUTHORITY\SYSTEM
Host: WORKSTATION-042
ParentImage: C:\Windows\CCM\CcmExec.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\Scripts\Deploy-Office365.ps1
```

**Why It Triggers:**
- `-ExecutionPolicy Bypass` flag matches suspicious indicator pattern
- SYSTEM account executing PowerShell could indicate privilege escalation

**How to Identify as Legitimate:**
1. **Parent Process:** CcmExec.exe is the SCCM client agent
2. **User Context:** NT AUTHORITY\SYSTEM is expected for SCCM deployments
3. **Script Path:** C:\Windows\CCM\ is the default SCCM client directory
4. **Timing:** Often executes during maintenance windows (overnight/early morning)
5. **Prevalence:** Same activity occurs across multiple workstations simultaneously

**Verification Query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ParentImage="*CcmExec.exe*" earliest=-1h
| stats dc(ComputerName) as affected_systems, values(ComputerName) as systems
| where affected_systems > 10
```

**Resolution:**
- Whitelist SCCM parent process when running as SYSTEM
- Optionally: Create separate alert for SCCM scripts with suspicious content (encoded commands, external connections)

**Tuning Applied:**
```spl
| where NOT (like(ParentImage, "%CcmExec.exe%") AND User="NT AUTHORITY\\SYSTEM")
```

---

#### FP Scenario 2: Group Policy Startup/Logon Scripts

**Example Event:**
```
Time: 2024-01-15 08:47:12
User: NT AUTHORITY\SYSTEM
Host: WORKSTATION-019
ParentImage: C:\Windows\System32\svchost.exe
CommandLine: powershell.exe -ExecutionPolicy RemoteSigned -File C:\Windows\SYSVOL\domain.corp.com\scripts\Map-Drives.ps1
```

**Why It Triggers:**
- PowerShell execution by SYSTEM account
- svchost.exe parent could indicate process injection

**How to Identify as Legitimate:**
1. **Script Path:** C:\Windows\SYSVOL\ is the domain Group Policy share
2. **Timing:** Often executes at user logon or system startup
3. **Parent Process:** svchost.exe is legitimate Windows service host
4. **User Context:** SYSTEM is expected for computer startup scripts
5. **Script Name:** Matches known GPO script (drive mapping, printer installation, registry updates)

**Verification Query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
CommandLine="*SYSVOL*" User="NT AUTHORITY\\SYSTEM" earliest=-24h
| stats count by CommandLine, ParentImage
```

**Resolution:**
- Whitelist svchost.exe spawning PowerShell as SYSTEM
- Validate script paths match domain SYSVOL structure
- Monitor for SYSVOL scripts with encoded commands (unusual for GPO)

**Tuning Applied:**
```spl
| where NOT (like(ParentImage, "%svchost.exe%") AND User="NT AUTHORITY\\SYSTEM")
```

---

### 2. Windows System Maintenance

**Frequency:** High (20-30% of all FPs)

**Common Sources:**
- Windows Update
- Windows Defender
- Scheduled Tasks
- System diagnostics and troubleshooting

---

#### FP Scenario 3: Windows Update Operations

**Example Event:**
```
Time: 2024-01-15 03:22:45
User: NT AUTHORITY\SYSTEM
Host: SERVER-WEB01
ParentImage: C:\Windows\System32\wuauclt.exe
CommandLine: powershell.exe -Command "Get-WindowsUpdate -Install -AcceptAll -AutoReboot"
```

**Why It Triggers:**
- SYSTEM account running PowerShell
- Could be persistence mechanism disguised as update

**How to Identify as Legitimate:**
1. **Parent Process:** wuauclt.exe is Windows Update client
2. **User Context:** SYSTEM is required for Windows Update
3. **Command Content:** Get-WindowsUpdate cmdlet is legitimate Windows Update module
4. **Timing:** Typically runs during maintenance windows (Patch Tuesday + 1-3 days)
5. **System Role:** Common on servers with automated patching

**Verification Query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ParentImage="*wuauclt.exe*" earliest=-7d
| timechart span=1d count
```
*Should show spikes on patch days*

**Resolution:**
- Whitelist wuauclt.exe parent as SYSTEM
- Monitor for unusual commands from wuauclt.exe (encoded, downloads, network connections)

**Tuning Applied:**
```spl
| where NOT (like(ParentImage, "%wuauclt.exe%") AND User="NT AUTHORITY\\SYSTEM")
```

---

#### FP Scenario 4: Windows Defender Scans

**Example Event:**
```
Time: 2024-01-15 11:33:19
User: NT AUTHORITY\SYSTEM
Host: WORKSTATION-088
ParentImage: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2201.10-0\MsMpEng.exe
CommandLine: powershell.exe -Command "Get-MpThreatDetection | Export-Csv C:\ProgramData\Defender\Logs\threats.csv"
```

**Why It Triggers:**
- PowerShell execution from unusual ProgramData path
- SYSTEM account could indicate compromise

**How to Identify as Legitimate:**
1. **Parent Process:** MsMpEng.exe is Windows Defender service
2. **Script Content:** Get-MpThreatDetection is legitimate Defender cmdlet
3. **File Path:** Writing to Defender logs directory
4. **User Context:** SYSTEM is expected for Defender operations

**Resolution:**
- Whitelist Windows Defender process paths
- Monitor for unusual commands from Defender (external connections, credential access)

---

### 3. IT Administration & Remote Management

**Frequency:** Medium (15-25% of all FPs)

**Common Sources:**
- Help desk remote support
- System administrator tasks
- Monitoring and management agents

---

#### FP Scenario 5: Help Desk Remote Support via WinRM

**Example Event:**
```
Time: 2024-01-15 14:22:11
User: CORP\helpdesk-tier1
Host: WORKSTATION-034
ParentImage: C:\Windows\System32\wsmprovhost.exe
CommandLine: powershell.exe -Command "Get-Process | Where-Object {$_.CPU -gt 50} | Select-Object Name,CPU,Memory"
```

**Why It Triggers:**
- PowerShell execution via remote management protocol
- Could be lateral movement or remote code execution

**How to Identify as Legitimate:**
1. **Parent Process:** wsmprovhost.exe is WinRM (Windows Remote Management) provider
2. **User Account:** Matches known help desk account naming convention
3. **Command Content:** Simple diagnostic commands (Get-Process, Get-Service, Get-EventLog)
4. **Timing:** During business hours when help desk is active
5. **Ticket Correlation:** Active support ticket for this user/host

**Verification Steps:**
1. Check ticketing system for open ticket
2. Verify user account is authorized for remote management
3. Review command complexity (simple diagnostics vs. encoded/obfuscated)

**Verification Query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ParentImage="*wsmprovhost.exe*" User="*helpdesk*" earliest=-7d
| stats count by User, CommandLine
```

**Resolution:**
- Whitelist wsmprovhost.exe for authorized help desk accounts
- Monitor for suspicious commands from help desk accounts (encoded, credential access, external connections)
- Alert on help desk accounts performing unusual actions

**Tuning Applied:**
```spl
| where NOT (like(ParentImage, "%wsmprovhost.exe%") AND like(User, "%helpdesk%"))
```

---

#### FP Scenario 6: System Administrator Scheduled Tasks

**Example Event:**
```
Time: 2024-01-15 00:05:02
User: CORP\svc-backup
Host: SERVER-FILE01
ParentImage: C:\Windows\System32\cmd.exe
CommandLine: powershell.exe -File C:\Scripts\Backup-EventLogs.ps1
```

**Why It Triggers:**
- Scheduled execution during off-hours
- Service account running PowerShell
- cmd.exe parent could indicate scripting chain

**How to Identify as Legitimate:**
1. **User Account:** Service account with clear naming (svc-backup, svc-admin)
2. **Script Path:** Standard administrative script directory (C:\Scripts\, C:\Admin\)
3. **Script Name:** Descriptive and matches known function (Backup, Monitor, Cleanup)
4. **Timing:** Consistent schedule (daily at midnight, weekly on Sundays)
5. **Prevalence:** Same script runs regularly without variation

**Verification Query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
CommandLine="*Backup-EventLogs.ps1*" earliest=-30d
| timechart span=1d count
```
*Should show regular daily pattern*

**Resolution:**
- Whitelist specific script paths and service accounts
- Verify script hash hasn't changed
- Monitor for modifications to whitelisted scripts

---

### 4. Development & Testing Environments

**Frequency:** Medium (10-20% of all FPs in environments with dev teams)

**Common Sources:**
- CI/CD pipelines
- Build automation
- Testing frameworks
- Developer workstations

---

#### FP Scenario 7: CI/CD Build Scripts

**Example Event:**
```
Time: 2024-01-15 16:45:33
User: CORP\jenkins-agent
Host: BUILD-SERVER-03
ParentImage: C:\Program Files\Jenkins\jre\bin\java.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\BuildScripts\Deploy-Application.ps1 -Environment UAT
```

**Why It Triggers:**
- Execution policy bypass
- Automated deployment could mask malicious activity

**How to Identify as Legitimate:**
1. **Host Naming:** BUILD-, DEV-, QA- prefixes indicate non-production
2. **User Account:** Service account for build automation (jenkins, teamcity, gitlab-runner)
3. **Parent Process:** Build tool executables (java.exe for Jenkins, node.exe for GitLab)
4. **Script Path:** Dedicated build/deployment directories
5. **Frequency:** Corresponds to development activity (frequent during business hours)

**Verification Query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ComputerName="BUILD-*" Image="*powershell.exe*" earliest=-7d
| timechart span=1h count by User
```

**Resolution:**
- Consider excluding build servers from this detection entirely
- If including build servers, whitelist known build service accounts and script paths
- Monitor for unusual activity (credential dumping, lateral movement from build servers)

---

#### FP Scenario 8: Developer Workstation Testing

**Example Event:**
```
Time: 2024-01-15 10:18:44
User: CORP\jsmith-dev
Host: DEV-WORKSTATION-12
ParentImage: C:\Program Files\Visual Studio Code\Code.exe
CommandLine: powershell.exe -File C:\Users\jsmith-dev\Projects\MyApp\scripts\test-api.ps1
```

**Why It Triggers:**
- PowerShell execution from user directory
- Code.exe parent could indicate exploitation

**How to Identify as Legitimate:**
1. **Host Naming:** DEV- prefix indicates developer workstation
2. **User Account:** Developer account with -dev suffix or similar naming
3. **Parent Process:** Development tools (Code.exe, devenv.exe, rider.exe)
4. **Script Path:** User's project directories
5. **User Role:** Confirmed developer in HR/IT systems

**Resolution:**
- Whitelist developer workstations (by hostname or OU)
- Monitor developer workstations for truly malicious activity (Mimikatz, credential dumping, external C2)
- Balance developer productivity with security monitoring

---

### 5. Security & Monitoring Tools

**Frequency:** Low-Medium (5-15% of all FPs)

**Common Sources:**
- EDR agents
- SIEM agents
- Vulnerability scanners
- Security assessment tools

---

#### FP Scenario 9: EDR Agent Diagnostics

**Example Event:**
```
Time: 2024-01-15 09:12:05
User: NT AUTHORITY\SYSTEM
Host: WORKSTATION-067
ParentImage: C:\Program Files\CrowdStrike\CSFalconService.exe
CommandLine: powershell.exe -Command "Get-Process | Select-Object Name,ID,Path | ConvertTo-Json"
```

**Why It Triggers:**
- PowerShell execution by security tool
- Could be malware disguised as security software

**How to Identify as Legitimate:**
1. **Parent Process:** Known EDR agent (CrowdStrike, SentinelOne, Carbon Black)
2. **Command Content:** Collecting system information for telemetry
3. **User Context:** SYSTEM is expected for security agents
4. **Installation:** EDR verified as legitimately deployed by security team

**Resolution:**
- Whitelist known EDR/security tool paths
- Verify with security team that tool is authorized
- Monitor for unusual commands from security tools

---

### 6. Legitimate Encoded PowerShell

**Frequency:** Low (2-5% of all FPs)

**Important Note:** While rare, some legitimate automation does use encoded commands, typically for handling special characters or passing complex parameters.

---

#### FP Scenario 10: Scheduled Task with Encoded Parameters

**Example Event:**
```
Time: 2024-01-15 01:00:00
User: CORP\svc-monitoring
Host: SERVER-MON01
ParentImage: C:\Windows\System32\svchost.exe
CommandLine: powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMQAwAA==
```

**Decoded Payload:**
```powershell
Start-Sleep -Seconds 10
```

**Why It Triggers:**
- Encoded command is primary malware indicator
- Service account with encoded PowerShell is suspicious

**How to Identify as Legitimate:**
1. **Decode the payload:** Content is simple, benign command
2. **User Context:** Known service account for monitoring
3. **Consistency:** Same encoded command executes on predictable schedule
4. **Business Justification:** IT can explain why encoding is used (e.g., scheduled task parameter limitation)

**Critical Distinction:**
**Malicious encoded commands typically:**
- Download content from external IPs
- Use Invoke-Expression (IEX) with remote content
- Access credentials or sensitive files
- Establish network connections

**Legitimate encoded commands typically:**
- Perform simple administrative tasks
- Don't make external connections
- Have clear business purpose when decoded
- Execute consistently without variation

**Resolution:**
- Decode ALL encoded commands before whitelisting
- Whitelist specific hash of encoded string (not just user/host combo)
- Re-verify if encoded string changes

---

## False Positive Remediation Strategies

### Strategy 1: Parent Process Filtering

**Most Effective For:** SCCM, GPO, Windows Update, Security Tools

**Implementation:**
```spl
| where NOT (
    (like(ParentImage, "%CcmExec.exe%") AND User="NT AUTHORITY\\SYSTEM") OR
    (like(ParentImage, "%svchost.exe%") AND User="NT AUTHORITY\\SYSTEM") OR
    (like(ParentImage, "%wuauclt.exe%") AND User="NT AUTHORITY\\SYSTEM")
)
```

**Advantages:**
- Highly effective at reducing noise
- Low risk of missing threats (legitimate parents rarely exploited)
- Easy to maintain and explain

**Risks:**
- Supply chain attacks could compromise legitimate tools
- Attackers could mimic legitimate parent process names (rare, requires privilege)

---

### Strategy 2: Script Path Whitelisting

**Most Effective For:** Scheduled tasks, administrative automation

**Implementation:**
```spl
| where NOT (
    like(CommandLine, "%C:\\Scripts\\Backup-%") AND User="CORP\\svc-backup"
)
```

**Advantages:**
- Very specific, low false positive impact
- Preserves detection for unusual execution paths

**Risks:**
- Requires maintenance as new scripts are added
- Attackers could place malicious scripts in whitelisted paths (requires write access)

---

### Strategy 3: Service Account Filtering

**Most Effective For:** Automated tasks, monitoring agents

**Implementation:**
```spl
| where NOT like(User, "%svc-%")
```

**Advantages:**
- Reduces noise from automated tasks
- Works across multiple scripts/systems

**Risks:**
- Broad whitelist - compromised service account could go undetected
- Should be combined with other filters (script path, command content)

---

### Strategy 4: Environmental Segmentation

**Most Effective For:** Development/test environments, build servers

**Implementation:**
```spl
| where NOT (
    like(ComputerName, "DEV-%") OR 
    like(ComputerName, "BUILD-%") OR 
    like(ComputerName, "QA-%")
)
```

**Advantages:**
- Dramatically reduces noise from development activity
- Allows developers to work without constant alerts

**Risks:**
- Development environments can be stepping stones to production
- Lateral movement from dev to prod would have reduced visibility

**Recommendation:** Consider separate, less-sensitive detection for dev environments rather than complete exclusion

---

### Strategy 5: Command Content Analysis

**Most Effective For:** Distinguishing benign from malicious commands

**Implementation:**
```spl
| where match(CommandLine, "(?i)downloadstring|downloadfile|invoke-expression|iex|net\.webclient")
```

**Advantages:**
- Focuses on truly malicious behavior
- Works across all parent processes and users

**Risks:**
- Requires understanding of attack techniques
- May miss novel or obfuscated methods

---

## Whitelist Decision Matrix

Use this matrix to decide if an event should be whitelisted:

| Criteria | Weight | Check |
|----------|--------|-------|
| Parent process is known management tool (SCCM, GPO) | HIGH | ☐ |
| User is SYSTEM or known service account | MEDIUM | ☐ |
| Script path is standard location (C:\Windows\CCM\, C:\Scripts\) | MEDIUM | ☐ |
| Command has no encoded/obfuscated content | HIGH | ☐ |
| No external network connections | HIGH | ☐ |
| Executes on predictable schedule | LOW | ☐ |
| Multiple systems show same pattern | MEDIUM | ☐ |
| IT/Security team confirms legitimacy | HIGH | ☐ |
| Hash matches known good script | MEDIUM | ☐ |
| No credential access or privilege escalation | HIGH | ☐ |

**Scoring:**
- **8-10 checks:** Strong whitelist candidate
- **5-7 checks:** Conditional whitelist (combine multiple filters)
- **<5 checks:** Do NOT whitelist - continue investigating

---

## Monitoring Whitelisted Activity

**Even whitelisted activity should be periodically reviewed:**

### Monthly Review Checklist:
```spl
# Check for changes in whitelisted scripts
index=windows sourcetype=WinEventLog:Sysmon EventCode=11 
TargetFilename="C:\\Scripts\\*.ps1"
| stats values(Hash) as observed_hashes by TargetFilename
```
```spl
# Look for unusual execution timing of whitelisted scripts
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
CommandLine="*Backup-Logs.ps1*"
| eval hour=strftime(_time, "%H")
| where hour >= 8 AND hour <= 18
| stats count by hour
```
*Should show minimal daytime activity for overnight scripts*
```spl
# Monitor for whitelisted accounts performing unusual actions
index=windows User="CORP\\svc-backup"
(TargetImage="*lsass.exe*" OR EventCode=4624 OR Image="*mimikatz*")
| table _time ComputerName EventCode Image CommandLine
```

---

## Common Mistakes in FP Handling

### ❌ Mistake 1: Over-Whitelisting

**Example:** `| where NOT like(User, "%SYSTEM%")`

**Problem:** Excludes ALL SYSTEM activity, including malware running with elevated privileges

**Better Approach:** Combine SYSTEM filter with parent process validation

---

### ❌ Mistake 2: Whitelisting by Hostname Only

**Example:** `| where NOT ComputerName="ADMIN-WS-01"`

**Problem:** Attacker compromising ADMIN-WS-01 would bypass detection entirely

**Better Approach:** Whitelist specific script + user + host combination

---

### ❌ Mistake 3: Not Decoding Before Whitelisting

**Example:** Whitelisting encoded command without knowing what it does

**Problem:** Could whitelist malicious encoded payload

**Better Approach:** ALWAYS decode and analyze content before whitelisting

---

### ❌ Mistake 4: Ignoring Context Changes

**Example:** Whitelisted script suddenly executes at unusual time or from different account

**Problem:** Script may be compromised or credentials stolen

**Better Approach:** Monitor for changes in execution pattern even for whitelisted activity

---

## Documentation Template

**When adding a whitelist, document:**
```
Date: 2024-01-15
Analyst: [Your Name]
Whitelist Type: Parent Process Filter
Filter Added: CcmExec.exe as SYSTEM
Reason: SCCM software deployments generating 200+ alerts/day, all confirmed legitimate
Verification: 
  - Confirmed with IT Ops team that SCCM is authorized deployment method
  - Reviewed 50 sample alerts, all showed legitimate software installation
  - Script paths all within C:\Windows\CCM\ directory
  - No encoded commands or external connections observed
Risk Assessment: Low - SCCM is trusted enterprise tool, supply chain attack risk accepted
Review Schedule: Quarterly
Approval: [Manager Name]
```

---

## Summary

**Key Takeaways:**

1. **90%+ of baseline PowerShell alerts are false positives** - effective tuning is essential
2. **Parent process analysis is the most effective FP reduction technique** - legitimate tools have predictable spawning patterns
3. **Context matters more than individual indicators** - `-ExecutionPolicy Bypass` from SCCM ≠ `-ExecutionPolicy Bypass` from Excel
4. **Never whitelist without understanding** - decode all encoded commands, verify all automation
5. **Whitelists require maintenance** - review quarterly, monitor for pattern changes
6. **Balance efficiency with security** - reduce noise without creating blind spots

**Final Principle:** When tuning detections, ask: "Would an attacker with these same attributes bypass my detection?" If yes, refine your filters.
