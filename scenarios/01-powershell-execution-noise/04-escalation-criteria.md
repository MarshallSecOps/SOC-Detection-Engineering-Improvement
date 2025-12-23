# PowerShell Execution - Escalation Criteria

## Overview

This document provides clear decision-making criteria for PowerShell execution alerts. The goal is to ensure high-confidence threats are escalated immediately while routine false positives are handled efficiently by Tier 1 analysts.

**Key Principle:** When in doubt, escalate. It's better to escalate a false positive than miss a real threat. However, clear benign patterns should be closed with documentation to build team knowledge.

---

## Decision Tree
```
PowerShell Alert Fires
    │
    ├─→ Risk Score 7+ (CRITICAL) ───→ Check System Criticality
    │                                      │
    │                                      ├─→ Domain Controller / Critical Server ───→ IMMEDIATE ESCALATION
    │                                      └─→ Workstation ───→ Investigate (5 min) ───→ Malicious indicators? ───→ ESCALATE
    │                                                                                  └─→ Benign? ───→ CLOSE
    │
    ├─→ Risk Score 5-6 (HIGH) ───→ Investigate (10 min) ───→ Clear malicious context? ───→ ESCALATE
    │                                                      └─→ Legitimate or unclear? ───→ DOCUMENT & CLOSE
    │
    ├─→ Risk Score 3-4 (MEDIUM) ───→ Investigate (10 min) ───→ Suspicious + related activity? ───→ ESCALATE
    │                                                        └─→ Isolated + benign context? ───→ CLOSE
    │
    └─→ Risk Score 1-2 (LOW) ───→ Quick validation (2 min) ───→ Known automation? ───→ WHITELIST & CLOSE
                                                               └─→ Unknown pattern? ───→ DOCUMENT & MONITOR
```

---

## Immediate Escalation (Do NOT Investigate Further)

**Escalate within 5 minutes of alert - notify Tier 2/IR team immediately**

### 1. Known Malware Signatures

**If CommandLine contains:**
- `Mimikatz`, `Invoke-Mimikatz`
- `Cobalt Strike`, `Beacon`
- `Meterpreter`, `Metasploit`
- `PowerSploit`, `Empire`, `Covenant`
- `Invoke-TheHash`, `Invoke-SMBExec`
- `sekurlsa::logonpasswords` (Mimikatz syntax)

**Action:** Immediate escalation - known post-exploitation framework

---

### 2. Critical System Compromise

**If ComputerName indicates:**
- Domain Controller (e.g., DC01, DC02)
- File server with sensitive data
- Database server
- Backup server
- Security infrastructure (SIEM, proxy, firewall)

**AND** Risk Score ≥ 7 (CRITICAL)

**Action:** Immediate escalation - critical infrastructure at risk

---

### 3. Privileged Account Compromise

**If User is:**
- Domain Admin account
- Enterprise Admin account
- Service account with elevated privileges (e.g., backup admin, SQL admin)

**AND** Activity is suspicious (encoded commands, unusual parent process)

**Action:** Immediate escalation - privileged credential compromise

---

### 4. Active Data Exfiltration

**If decoded CommandLine contains:**
- `Compress-Archive` with network destination
- `Send-MailMessage` with attachments from sensitive paths
- Data staging to external shares: `\\<external_ip>\share`
- Large file uploads to cloud services (non-corporate)

**AND** Network activity shows large outbound data transfer

**Action:** Immediate escalation - active data theft

---

### 5. Confirmed C2 Communication

**If network analysis shows:**
- Connection to known malicious IP (threat intel match)
- Beaconing pattern (regular intervals like every 60 seconds)
- High-entropy domain names (e.g., `af8d9f3g2h.com`)
- Unusual destination ports (not 80/443/53)

**Action:** Immediate escalation - command and control activity

---

## Escalate After Investigation

**Investigate for 10-15 minutes, then escalate with findings documented**

### 1. Encoded PowerShell with Suspicious Context

**Criteria:**
- CommandLine contains `-e`, `-enc`, `-encodedcommand`
- Parent process is suspicious (Office apps, Downloads, user-spawned cmd.exe)
- User is NOT IT/admin with documented need for encoded scripts

**Investigation required:**
- Decode the payload
- Check for IOCs (IPs, domains, file paths)
- Verify user's normal PowerShell usage patterns

**If decoded payload shows:**
- DownloadString/DownloadFile from external sources
- Invoke-Expression (IEX) with remote content
- Obfuscated variable names or string manipulation
- Network sockets or reverse shell syntax

**Action:** Escalate with decoded payload and IOCs

---

### 2. PowerShell from Office Applications

**Criteria:**
- ParentImage = EXCEL.EXE, WINWORD.EXE, POWERPNT.EXE, OUTLOOK.EXE
- User is regular employee (not developer/admin)

**Investigation required:**
- Check if user regularly works with macros (finance, operations roles may be legitimate)
- Review email logs for recent external emails with attachments
- Check file creation events for suspicious executables

**If investigation shows:**
- User does NOT normally use macros
- Recent external email with attachment
- Suspicious file creation after macro execution

**Action:** Escalate as phishing/macro malware

**If investigation shows:**
- User regularly uses macro-enabled documents
- Internal template or known business process
- No suspicious file creation or network activity

**Action:** Document and close (consider educating user on macro security)

---

### 3. Off-Hours Activity from Non-IT Accounts

**Criteria:**
- Execution time: 10pm - 6am OR weekends
- User is NOT IT staff or system administrator
- Risk score ≥ 5 (HIGH)

**Investigation required:**
- Check user's normal work schedule
- Review VPN logs (are they connected remotely?)
- Search for related suspicious activity

**If investigation shows:**
- User is NOT on VPN
- No legitimate business reason for off-hours access
- Related suspicious activity (credential dumping, lateral movement)

**Action:** Escalate as compromised account

**If investigation shows:**
- User is on VPN from known location
- Legitimate overtime work or on-call rotation
- No other suspicious indicators

**Action:** Document and close

---

### 4. First-Time PowerShell Usage

**Criteria:**
- User has NO history of PowerShell execution in past 90 days
- Suddenly executes encoded or obfuscated PowerShell

**Investigation required:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
User=<ALERT_USER> Image="*powershell.exe" earliest=-90d
| stats count by _time, CommandLine
```

**If investigation shows:**
- This is truly first PowerShell usage
- User role does not require scripting (e.g., finance, HR, sales)
- Command is obfuscated or downloads content

**Action:** Escalate as anomalous behavior

**If investigation shows:**
- User is new employee in IT/DevOps role
- Command is simple administrative task
- Manager confirms legitimate onboarding task

**Action:** Document and close

---

### 5. Lateral Movement Indicators

**Criteria:**
- PowerShell execution on multiple hosts in short timeframe
- Same user account appearing on systems they don't normally access
- WinRM/PSRemoting activity from workstation-to-workstation

**Investigation required:**
```spl
index=windows EventCode=4624 Account_Name=<ALERT_USER> Logon_Type=3 earliest=-1h
| stats dc(ComputerName) as unique_systems, values(ComputerName) as systems_accessed
```

**If investigation shows:**
- User accessed 5+ systems in 1 hour
- Systems include servers or workstations outside user's normal scope
- Pattern indicates scanning or reconnaissance

**Action:** Escalate as lateral movement

**If investigation shows:**
- IT administrator performing maintenance
- Systems are within user's normal scope (e.g., admin managing server farm)
- Documented maintenance window

**Action:** Document and close

---

## Investigate & Close (No Escalation)

**Investigate to confirm legitimacy, document findings, close ticket**

### 1. Known Automation Scripts

**Criteria:**
- CommandLine references script in standard location: `C:\Scripts\`, `C:\Admin\`
- Script name matches known automation (Backup-Logs.ps1, Deploy-Software.ps1)
- User is service account or IT administrator

**Investigation required:**
- Verify script hash against known good scripts
- Check if script path is consistent with previous executions
- Confirm user has legitimate access to run this automation

**Verification query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
CommandLine="*<script_name>.ps1*" earliest=-30d
| stats count by User, ComputerName, CommandLine
```

**If consistent pattern (same script, same account, regular schedule):**
**Action:** Document as legitimate automation, close ticket

**If inconsistent (new script, different account, unusual timing):**
**Action:** Escalate for validation

---

### 2. SCCM / Group Policy Deployments

**Criteria:**
- ParentImage = CcmExec.exe, svchost.exe, services.exe
- User = NT AUTHORITY\SYSTEM
- Script path = C:\Windows\CCM\, C:\Windows\SYSVOL\

**Investigation required:**
- Verify script path is legitimate SCCM/GPO location
- Check if deployment window matches scheduled maintenance
- Confirm multiple systems show same activity (mass deployment)

**Verification query:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1 
ParentImage="*CcmExec.exe*" CommandLine="*<script_name>*" earliest=-1h
| stats dc(ComputerName) as affected_hosts
```

**If affected_hosts > 10 (mass deployment):**
**Action:** Document as SCCM deployment, close ticket

**If affected_hosts = 1-2 (isolated execution):**
**Action:** Investigate further or escalate

---

### 3. Windows Update / System Maintenance

**Criteria:**
- ParentImage = wuauclt.exe, TrustedInstaller.exe
- User = NT AUTHORITY\SYSTEM
- CommandLine contains Get-WindowsUpdate, Install-WindowsUpdate

**Investigation required:**
- Verify execution time matches patch Tuesday or scheduled maintenance
- Check other systems for similar activity

**Action:** Document as Windows Update, close ticket

---

### 4. Help Desk Remote Support

**Criteria:**
- ParentImage = wsmprovhost.exe (WinRM provider)
- User is known help desk account (CORP\helpdesk01, CORP\itsupport)
- CommandLine is simple diagnostic command (Get-Process, Get-EventLog)

**Investigation required:**
- Check ticketing system for open support ticket for this user/host
- Verify help desk account is authorized for remote management
- Confirm timing matches ticket creation

**If ticket exists and timing matches:**
**Action:** Document as legitimate support, close ticket

**If no ticket or suspicious commands:**
**Action:** Escalate as potential compromised help desk account

---

### 5. Developer Workstations

**Criteria:**
- ComputerName indicates developer workstation (DEV-, QA-, BUILD-)
- User is known developer or DevOps engineer
- CommandLine shows build scripts, deployment automation, or testing

**Investigation required:**
- Verify user role (check HR system or IT asset database)
- Check if activity aligns with development work (e.g., CI/CD pipeline)

**If legitimate development work:**
**Action:** Document and close, consider excluding dev workstations from this detection if noise is high

**If suspicious (encoded commands, external connections, credential dumping):**
**Action:** Escalate - developers should not be running malware-like commands

---

## Document & Whitelist

**For repeated legitimate activity creating consistent noise**

### Criteria for Whitelisting:

1. **Consistent pattern:** Same script, same account, same systems, regular schedule
2. **Verified legitimacy:** Confirmed with IT/security team as approved automation
3. **Low risk:** No encoded commands, no external connections, trusted parent process
4. **Volume impact:** Generating 10+ alerts per day with zero true positives

### Whitelist Implementation:

**Add to tuned detection:**
```spl
| where NOT (
    ... existing whitelists ...
    OR (like(CommandLine, "%Backup-Logs.ps1%") AND User="CORP\\svc-backup")
)
```

**Document whitelist addition:**
```
Date: 2024-01-15
Analyst: [Your Name]
Whitelist Added: Backup-Logs.ps1 by svc-backup account
Reason: Legitimate nightly backup automation, verified with IT Ops team
Verification: Script hash abc123def456, executes at 2am daily, no suspicious activity
```

---

## Escalation Communication Template

**When escalating to Tier 2/IR team, provide:**
```
ESCALATION: PowerShell Execution Alert
SEVERITY: [CRITICAL / HIGH]
TIME: [Timestamp]
ANALYST: [Your Name]

ALERT SUMMARY:
Host: [ComputerName]
User: [Username]
Risk Score: [Score]
Parent Process: [ParentImage]

INITIAL FINDINGS:
[Bullet points of key findings from investigation]

DECODED PAYLOAD (if applicable):
[Paste decoded PowerShell command]

INDICATORS OF COMPROMISE:
- IP: [if applicable]
- Domain: [if applicable]
- File: [if applicable]

RECOMMENDED ACTIONS:
- [ ] Isolate host from network
- [ ] Disable user account
- [ ] Collect forensic image
- [ ] Reset credentials
- [ ] Hunt for lateral movement

RELATED TICKETS: [Link to related incidents if applicable]
```

---

## Common Escalation Mistakes

### ❌ Don't Escalate If:
- Known SCCM/GPO automation running as SYSTEM from legitimate paths
- IT admin performing documented maintenance during approved window
- Help desk remote support with matching ticket
- Developer workstation running build scripts (unless clearly malicious)

### ✅ Always Escalate If:
- Decoded payload contains DownloadString/DownloadFile from external IPs
- Office application spawning encoded PowerShell
- Domain Controller or critical server compromised
- Known malware keywords in command line
- Privileged account (Domain Admin) executing suspicious commands

---

## Metrics to Track

**For continuous improvement:**

| Metric | Target | Review Frequency |
|--------|--------|------------------|
| Escalation Rate | 5-10% of total alerts | Weekly |
| False Escalation Rate | <10% of escalations | Monthly |
| Missed Threat Rate | 0% | Monthly (via threat hunt) |
| Avg Time to Escalate | <15 minutes | Weekly |
| Whitelist Effectiveness | Reduces alerts by 20%+ | Quarterly |

---

## Training & Calibration

**New analysts should:**
1. Shadow 10 investigations with senior analyst
2. Present escalation decisions for review before submitting
3. Participate in weekly detection calibration meetings
4. Review missed/false escalations as learning opportunities

**Team calibration:**
- Monthly review of borderline cases
- Discuss false escalations without blame
- Update criteria based on environment changes
- Share lessons learned from IR investigations

---

## Quick Reference

| Situation | Action | Time Limit |
|-----------|--------|------------|
| Mimikatz in command line | IMMEDIATE ESCALATE | <5 min |
| Domain Controller + Risk 7+ | IMMEDIATE ESCALATE | <5 min |
| Excel spawning encoded PS | Investigate → ESCALATE | 10 min |
| SCCM deployment | DOCUMENT & CLOSE | 5 min |
| Off-hours from VPN | Investigate → DECIDE | 10 min |
| Help desk with ticket | DOCUMENT & CLOSE | 5 min |
| Repeated legitimate automation | WHITELIST | After 3rd occurrence |

---

## References

- Investigation Playbook: `03-investigation-playbook.md`
- False Positive Analysis: `05-false-positive-analysis.md`
- Tuning Rationale: `06-tuning-rationale.md`
