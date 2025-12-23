# Failed Login Attempts / Brute Force - Investigation Playbook

## Overview

This playbook provides step-by-step procedures for investigating failed login attempt alerts. The goal is to quickly determine if the activity represents a legitimate user error or malicious brute force/password spray attack, gather evidence, and make appropriate escalation decisions.

**Average Investigation Time:** 5-10 minutes for routine triage, 15-30 minutes for deeper investigation

---

## Triage Workflow

### Step 1: Review Alert Context (1-2 minutes)

**Gather basic information:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<ALERT_IP> earliest=-30m
| stats count as failure_count, 
    dc(TargetUserName) as unique_users,
    values(TargetUserName) as target_users,
    values(SubStatus) as failure_reasons
    by IpAddress
| eval risk_score = [from tuned detection]
```

**Key Questions:**
- **When?** Business hours (8am-6pm) or off-hours?
- **Where from?** External IP (public internet) or internal IP (RFC1918)?
- **Who targeted?** Privileged accounts (admin, svc-) or regular users?
- **What severity?** Risk score from tuned detection (CRITICAL = 10+, HIGH = 7-9)

**Initial Assessment:**
- CRITICAL severity + success_count > 0 = Immediate escalation, skip to Step 6
- CRITICAL severity + external source = Continue investigation urgently
- HIGH/MEDIUM severity = Continue standard triage
- LOW severity + internal source = Quick validation, likely close

---

### Step 2: Analyze Source IP (2-3 minutes)

**Check source IP characteristics:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<ALERT_IP> earliest=-24h
| stats count by IpAddress, TargetUserName
```

**Decision Tree:**

**If Source = RFC1918 (10.x, 172.16.x, 192.168.x):**
- → Internal source, check if legitimate user/system
- → Look up IP in asset inventory (workstation, server, VPN gateway?)
- → Check historical authentication patterns from this IP
- → If known user workstation + single account failures → Likely password reset/typo
- → If VPN gateway + service account → Likely connection retry loop
- → If unknown IP or spray pattern → Investigate as potential compromised internal host

**If Source = External (Public Internet):**
- → HIGH suspicion automatically
- → Check IP reputation (VirusTotal, AbuseIPDB, threat intel)
- → Verify if IP is known VPN endpoint or legitimate remote access
- → If known malicious IP → Immediate escalation
- → If unknown IP with spray pattern → Continue to Step 3

**If Source = Cloud Provider Range (AWS, Azure, GCP):**
- → Could be legitimate SaaS/cloud services OR attacker infrastructure
- → Check ASN/organization name
- → Verify if organization uses these cloud services
- → Cross-reference with approved remote access IPs

---

### Step 3: Analyze Failure Pattern (2-4 minutes)

**Check attack methodology:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<ALERT_IP> earliest=-30m
| bin _time span=1m
| stats count by _time, TargetUserName
| timechart span=1m count by TargetUserName
```

**Pattern Recognition:**

**Brute Force (Single Account, High Volume):**
- Same username, many password attempts
- Rapid succession (50+ attempts in 5 minutes)
- Often targets admin/privileged accounts
- Example: 87 failures against "Administrator" in 10 minutes

**Password Spray (Multiple Accounts, Low Volume per Account):**
- Many different usernames, few attempts each
- Systematic (alphabetical, common names)
- Trying common passwords across accounts
- Example: 8 accounts with 3-6 failures each

**Credential Stuffing (Breached Credentials):**
- Mix of valid and invalid usernames
- Variable failure rates
- Often from botnet IPs
- Example: 50+ accounts, mostly non-existent usernames (SubStatus 0xC0000064)

**Legitimate User Error:**
- Single username, 3-10 attempts
- Eventually successful (check Event ID 4624)
- Reasonable time spacing (not automated)
- Example: 6 failures over 5 minutes, then success

---

### Step 4: Check Target Account Context (2-3 minutes)

**Analyze accounts being targeted:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<ALERT_IP> earliest=-30m
| stats count by TargetUserName
| sort -count
```

**Red Flags:**
- **Privileged accounts:** Administrator, admin, svc-*, *-admin, domain admin accounts
- **Service accounts:** svc-*, sa-*, service-*
- **Generic accounts:** admin, test, user, backup, root
- **Account enumeration:** Non-existent usernames (SubStatus 0xC0000064)
- **Executive/high-value targets:** CEO, CFO, finance accounts

**Green Flags:**
- **Single regular user:** jsmith, mbrown (non-privileged)
- **Known problematic user:** User who frequently forgets password
- **Recent password change:** User re-entering old password

**Check account attributes:**
```spl
| inputlookup active_directory_users.csv
| search username=<TARGET_USER>
| table username, is_admin, is_service_account, last_password_change, account_status
```

---

### Step 5: Check Success Correlation (CRITICAL - 2-3 minutes)

**Look for successful logins after failures:**
```spl
index=windows sourcetype=WinEventLog:Security 
(EventCode=4625 OR EventCode=4624) IpAddress=<ALERT_IP> earliest=-30m
| eval event_type = case(
    EventCode=4625, "FAILURE",
    EventCode=4624, "SUCCESS"
)
| table _time event_type TargetUserName IpAddress WorkstationName
| sort _time
```

**If Success Found After Failures:**
- **CRITICAL INDICATOR** - Attacker obtained valid credentials
- Check successful login details:
  - Time between last failure and success
  - Account that succeeded
  - Logon type (Network=3, Interactive=2, RemoteInteractive=10)
  - System accessed

**Immediate Actions Required:**
1. Note compromised account(s)
2. Check for post-authentication activity (lateral movement, data access)
3. Skip remaining steps → Immediate escalation

**If No Success Found:**
- Attack failed (so far)
- Continue investigation to assess ongoing threat
- Monitor for continued attempts or success in near future

---

### Step 6: Analyze SubStatus Codes (1-2 minutes)

**Check failure reasons:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<ALERT_IP> earliest=-30m
| stats count by SubStatus
```

**SubStatus Code Meanings:**

**0xC000006A - Bad Password:**
- Most common for brute force
- Attacker trying different passwords
- Also common for legitimate user typos

**0xC0000064 - User Name Does Not Exist:**
- **Account enumeration attempt**
- Attacker probing for valid usernames
- Multiple unique usernames with this code = scanning

**0xC0000234 - Account Locked Out:**
- Result of too many failures
- Check if lockout occurred during attack window
- Verify legitimate user isn't locked out accidentally

**0xC0000072 - Account Disabled:**
- Attacker trying disabled accounts
- Could be old credentials from breach

**0xC0000071 - Password Expired:**
- Legitimate user with expired password
- Or attacker with old credentials

**0xC0000193 - Account Expired:**
- Attacker using old/stale credentials
- Check if account is old termination

---

### Step 7: Search for Related Activity (3-5 minutes)

**Check for additional suspicious activity:**

**A. Other authentication attempts from same source:**
```spl
index=windows sourcetype=WinEventLog:Security 
(EventCode=4625 OR EventCode=4624 OR EventCode=4648) 
IpAddress=<ALERT_IP> earliest=-24h
| stats count by EventCode, TargetUserName, ComputerName
```

**B. Lateral movement attempts (if successful login occurred):**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624
Account_Name=<COMPROMISED_USER> Logon_Type=3 earliest=-1h
| stats count by ComputerName, Source_Network_Address
| where Source_Network_Address!=<ORIGINAL_IP>
```

**C. Failed logins across multiple systems:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
TargetUserName=<ALERT_USER> earliest=-24h
| stats count by ComputerName, IpAddress
```

**D. VPN connection attempts (if internal source):**
```spl
index=vpn (status=failure OR status=success) 
user=<ALERT_USER> OR src_ip=<ALERT_IP> earliest=-24h
| table _time user src_ip status
```

**E. Previous attack attempts from same IP:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
IpAddress=<ALERT_IP> earliest=-7d
| timechart span=1h count by TargetUserName
```

---

### Step 8: Make Escalation Decision (1-2 minutes)

**Use decision tree from `04-escalation-criteria.md`**

**Immediate Escalation (Do NOT investigate further):**
- Successful login after failures from external source
- Brute force against Domain Admin or privileged service account
- Password spray targeting >10 privileged accounts
- Source IP is known malicious (threat intel hit)
- Risk score 10+ with confirmed compromise

**Escalate After Investigation:**
- External source with spray pattern (no success yet)
- Internal source with unusual spray pattern (possible compromised host)
- Off-hours authentication attempts from external IP
- Account enumeration (SubStatus 0xC0000064) targeting multiple accounts
- Risk score 7-9 with suspicious indicators

**Document & Close:**
- Internal single-user password errors with eventual success
- Known VPN retry patterns from legitimate infrastructure
- Service account lockouts with documented rotation activity
- Risk score 1-3 with clear benign context

---

## Investigation Examples

### Example 1: CRITICAL - External Password Spray with Success

**Alert:**
```
Time: 2024-01-15 18:47:33
Source IP: 203.0.113.45 (External)
Target Users: jsmith, mbrown, akumar, tjohnson, rlee, swilliams, dchen, mgarcia
Failure Count: 48 failures
Unique Users: 8 accounts
Success Count: 1 (jsmith succeeded)
Risk Score: 14 (CRITICAL)
```

**Step 1 - Context:** After hours, external source, multiple users → HIGH priority

**Step 2 - Source IP:** 
- 203.0.113.45 is external (public internet)
- AbuseIPDB: Reported 15 times for brute force attacks
- Not in organization's approved remote access IPs

**Step 3 - Pattern:** Password spray pattern (8 accounts, ~6 failures each)

**Step 4 - Targets:** Regular users, no privileged accounts

**Step 5 - Success Correlation:**
- **CRITICAL:** jsmith account succeeded at 18:52 (5 minutes after failures)
- Logon Type: 3 (Network logon)
- Accessed: FILE-SERVER-01

**Step 6 - SubStatus:** All 0xC000006A (bad password)

**Step 7 - Related Activity:**
- jsmith account accessed FILE-SERVER-01 at 18:53
- File access: \\FILE-SERVER-01\Finance\Q4_Reports\
- No lateral movement to other systems yet

**Decision: IMMEDIATE ESCALATION**
- External password spray resulted in account compromise
- Attacker accessed file server with compromised credentials
- **Actions:** Disable jsmith account, isolate FILE-SERVER-01, check file access logs, hunt for data exfiltration

---

### Example 2: FALSE POSITIVE - VPN Retry Loop

**Alert:**
```
Time: 2024-01-15 09:15:20
Source IP: 10.10.10.5 (VPN Gateway)
Target User: svc-vpn
Failure Count: 45 failures
Unique Users: 1
Risk Score: 0 (filtered by whitelist, manual review)
```

**Step 1 - Context:** Business hours, internal IP, service account → Check automation

**Step 2 - Source IP:** 
- 10.10.10.5 is VPN-GW-01 (known VPN infrastructure)
- Asset inventory confirms VPN gateway
- Historical pattern: svc-vpn has regular authentication from this IP

**Step 3 - Pattern:** 
- Single account (svc-vpn), high volume
- Failures clustered in 5-minute window
- Repeated every 5 seconds (automated retry)

**Step 4 - Targets:** svc-vpn (known VPN service account)

**Step 5 - Success Correlation:**
- No successful logins during window
- IT ticket #12847: "VPN gateway password sync issue - resolved 09:25"

**Step 6 - SubStatus:** All 0xC000006A (bad password)

**Step 7 - Related Activity:**
- Same pattern occurred last month during service account rotation
- svc-vpn successfully authenticated from same IP at 09:30 (after fix)

**Decision: DOCUMENT & CLOSE**
- Known VPN infrastructure issue
- Service account password mismatch resolved by IT
- Add to whitelist monitoring notes

---

### Example 3: ESCALATE - External Brute Force Against Admin

**Alert:**
```
Time: 2024-01-15 03:22:15
Source IP: 198.51.100.67 (External)
Target User: Administrator
Failure Count: 87 failures
Unique Users: 1
Success Count: 0
Risk Score: 9 (HIGH)
```

**Step 1 - Context:** Off-hours (3am), external source, admin account → HIGH priority

**Step 2 - Source IP:**
- 198.51.100.67 is external (public internet)
- VirusTotal: 3/92 engines flag as malicious
- ASN: AS12345 "Generic Hosting Provider LLC"
- Not in organization's approved remote access

**Step 3 - Pattern:**
- Brute force (single account, high volume)
- 87 attempts in 15 minutes (~6 per minute)
- Automated tool signature (consistent timing)

**Step 4 - Targets:** Administrator (built-in privileged account)

**Step 5 - Success Correlation:** No successful logins (attack failed)

**Step 6 - SubStatus:** All 0xC000006A (bad password attempts)

**Step 7 - Related Activity:**
- Same IP attempted authentication against 3 other domain controllers
- Total 247 failures across all DCs in 30-minute window
- No successful logins on any system

**Decision: ESCALATE AFTER INVESTIGATION**
- Organized brute force attack against privileged account
- Attack failed but demonstrates threat actor reconnaissance
- **Actions:** Block source IP at firewall, review admin account security, enable account lockout threshold, monitor for continued attempts

---

### Example 4: MEDIUM - Internal Spray Pattern (Compromised Host)

**Alert:**
```
Time: 2024-01-15 14:30:45
Source IP: 10.50.20.15 (Internal Workstation)
Target Users: user1, user2, user3, user4, user5, user6, user7
Failure Count: 28 failures
Unique Users: 7
Success Count: 0
Risk Score: 5 (MEDIUM)
```

**Step 1 - Context:** Business hours, internal source, multiple users → Investigate

**Step 2 - Source IP:**
- 10.50.20.15 is WORKSTATION-22 (jdoe assigned)
- Asset inventory: Standard user workstation, finance department

**Step 3 - Pattern:**
- Password spray (7 accounts, 4 failures each)
- Systematic pattern suggests automated tool

**Step 4 - Targets:** Regular users, no privileged accounts

**Step 5 - Success Correlation:** No successful logins

**Step 6 - SubStatus:** All 0xC000006A (bad password)

**Step 7 - Related Activity:**
- EDR logs: Unknown process "pws.exe" running on WORKSTATION-22
- Process creation: 14:25 (5 minutes before failures)
- Parent process: Excel.exe (macro execution)
- Network connection: WORKSTATION-22 → 192.168.10.50:443

**Decision: ESCALATE AFTER INVESTIGATION**
- Internal workstation compromised via macro malware
- Malware attempting password spray from internal position
- **Actions:** Isolate WORKSTATION-22, disable jdoe account, collect forensics, hunt for lateral movement

---

### Example 5: CLOSE - User Password Reset

**Alert:**
```
Time: 2024-01-15 09:05:12
Source IP: 10.80.15.33 (Internal Workstation)
Target User: mbrown
Failure Count: 8 failures
Unique Users: 1
Success Count: 1
Risk Score: 2 (LOW)
```

**Step 1 - Context:** Business hours, internal source, single user → Quick check

**Step 2 - Source IP:**
- 10.80.15.33 is WORKSTATION-15 (mbrown assigned)
- Asset inventory: User's regular workstation

**Step 3 - Pattern:**
- 8 failures over 4 minutes
- Successful login after 8th attempt
- Not automated (variable timing)

**Step 4 - Targets:** mbrown (non-privileged user)

**Step 5 - Success Correlation:**
- Successfully logged in at 09:09
- Same workstation, same account
- Normal business operations resumed

**Step 6 - SubStatus:** All 0xC000006A (bad password)

**Step 7 - Related Activity:**
- Help desk ticket #5432: "User requested password reset" at 09:00
- mbrown changed password via self-service portal at 09:03
- Failures occurred during transition period (old password cached)

**Decision: DOCUMENT & CLOSE**
- Legitimate user password reset scenario
- User entered old password multiple times before remembering new one
- No security concern

---

## Common Pitfalls

**Don't assume internal = safe**
- Internal sources can be compromised workstations/servers
- Password spray from internal IP may indicate malware infection

**Don't ignore "unsuccessful" attacks**
- Failed brute force today = reconnaissance for tomorrow
- Blocking and documenting prevents future success

**Don't forget time zones**
- "After hours" depends on user location
- Remote workers may authenticate from different time zones

**Don't overlook service accounts**
- Service account failures can indicate misconfiguration
- But also can hide in automation noise while being targeted

**Don't skip success correlation**
- Most important step - separates attempt from compromise
- Even 1 success after 100 failures = critical incident

---

## Quick Reference - SPL Queries

**Get failure details:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<IP> earliest=-30m
| stats count by TargetUserName, SubStatus, WorkstationName
```

**Check for successful logins:**
```spl
index=windows sourcetype=WinEventLog:Security 
(EventCode=4625 OR EventCode=4624) IpAddress=<IP> earliest=-30m
| table _time EventCode TargetUserName IpAddress
| sort _time
```

**Find spray pattern:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 
IpAddress=<IP> earliest=-30m
| stats count by TargetUserName
| sort -count
```

**Check historical attempts:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
IpAddress=<IP> earliest=-7d
| timechart span=1h count
```

**Lateral movement check:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624
Account_Name=<USER> Logon_Type=3 earliest=-1h
| stats count by ComputerName, Source_Network_Address
```

---

## Tools & Resources

**IP Reputation:**
- VirusTotal: https://www.virustotal.com/
- AbuseIPDB: https://www.abuseipdb.com/
- AlienVault OTX: https://otx.alienvault.com/
- Shodan: https://www.shodan.io/

**SubStatus Code Reference:**
- Microsoft Documentation: https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625

**MITRE ATT&CK:**
- T1110.001: https://attack.mitre.org/techniques/T1110/001/
- T1110.003: https://attack.mitre.org/techniques/T1110/003/

---

## Documentation Template
```
ALERT: Failed Login Attempts - [Risk Score]
TIME: [Timestamp]
ANALYST: [Your Name]
SOURCE IP: [IpAddress]
TARGET USERS: [List of accounts]

SUMMARY:
[2-3 sentence description of what happened]

INVESTIGATION STEPS:
[Timestamp] - Alert received, began triage
[Timestamp] - Analyzed source IP: [findings]
[Timestamp] - Checked failure pattern: [findings]
[Timestamp] - Reviewed target accounts: [findings]
[Timestamp] - Checked success correlation: [findings]
[Timestamp] - Analyzed SubStatus codes: [findings]
[Timestamp] - Searched related activity: [findings]

INDICATORS:
- Source IP: [IP address]
- Reputation: [threat intel findings]
- Pattern: [brute force / password spray / credential stuffing]
- Success: [Yes/No - if yes, list compromised accounts]
- SubStatus: [failure reasons]

ANALYSIS:
[Detailed explanation of findings]

DECISION: [ESCALATED / CLOSED]
REASON: [Justification for decision]

ACTIONS TAKEN:
- [List any containment or follow-up actions]
```
