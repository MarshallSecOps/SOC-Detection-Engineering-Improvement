# Investigation Playbook: Unusual Network Connections

## Purpose
This playbook provides step-by-step procedures for triaging alerts from the Unusual Network Connections detection. The goal is to quickly determine if network traffic represents legitimate business activity, requires further investigation, or warrants immediate escalation.

**Target Triage Time:** 8-12 minutes for MEDIUM severity, 3-5 minutes for CRITICAL severity

---

## Investigation Workflow

### Step 1: Initial Alert Review (1-2 minutes)

**Objective:** Understand the basic alert context and prioritize investigation effort based on severity

**Actions:**
1. Review the alert severity (CRITICAL / HIGH / MEDIUM / LOW)
2. Note the risk score and which indicators contributed to it
3. Identify the source IP, destination domain/IP, port, and protocol
4. Check connection count, data volume, and timing patterns
5. Note if user context is available or missing

**Key Questions:**
- What severity level is this alert?
- Is this a high-volume beaconing pattern or large data upload?
- Is the destination a direct IP or domain name?
- Are there associated user accounts?

**Decision Point:**
- **CRITICAL (10+):** Proceed immediately to Step 2, treat as active incident
- **HIGH (7-9):** Standard investigation flow, prioritize over MEDIUM alerts
- **MEDIUM (4-6):** Standard investigation flow, lower priority

---

### Step 2: Source Asset Identification (1-2 minutes)

**Objective:** Identify what system initiated the connection and assess criticality

**SPL Query:**
```spl
| inputlookup asset_inventory.csv
| search ip="<SOURCE_IP>"
| table ip hostname asset_type owner department criticality
```

**Manual Verification (if asset inventory unavailable):**
- DNS reverse lookup: `nslookup <SOURCE_IP>`
- Active Directory computer object lookup
- CMDB / asset management system query

**Key Questions:**
- What type of asset is this? (workstation, server, Domain Controller, POS terminal)
- What is the asset criticality level? (CRITICAL, HIGH, MEDIUM, LOW)
- Who is the asset owner/primary user?
- What department/business function does this asset support?

**Red Flags:**
- ❌ Domain Controllers or other critical infrastructure
- ❌ POS terminals or isolated network segments
- ❌ Database servers or file servers
- ❌ Jump boxes or privileged access workstations

**Decision Point:**
- If asset is CRITICAL infrastructure (DC, database, jump box) → **Immediate escalation**
- If asset is standard workstation/server → Continue investigation

---

### Step 3: Destination Reputation Analysis (2-3 minutes)

**Objective:** Determine if the destination is known-malicious, suspicious, or potentially legitimate

**Online Reputation Checks:**
1. **VirusTotal:** `https://www.virustotal.com/gui/domain/<DOMAIN>` or `https://www.virustotal.com/gui/ip-address/<IP>`
   - Check detection ratio (e.g., 5/89 vendors flagged as malicious)
   - Review community comments and historical analysis
   - Check domain creation date (newly registered domains suspicious)

2. **AbuseIPDB:** `https://www.abuseipdb.com/check/<IP>`
   - Check abuse confidence score (>75% = high confidence malicious)
   - Review reported categories (port scan, brute force, malware)

3. **Cisco Talos Intelligence:** `https://talosintelligence.com/reputation_center/lookup?search=<IP or DOMAIN>`
   - Check email/web reputation scores
   - Review categorization (malware, spam, botnets)

4. **WHOIS Lookup:** `whois <DOMAIN>`
   - Check domain registration date (created in last 30 days = suspicious)
   - Check registrar (some registrars known for abuse)
   - Check registrant country (matches expected business geography?)

**SPL Query - Check Internal Threat Intelligence:**
```spl
| inputlookup threat_intel_iocs.csv
| search indicator="<DEST_IP>" OR indicator="<DEST_DOMAIN>"
| table indicator type threat_name severity last_seen source
```

**Key Questions:**
- Is this IP/domain flagged by threat intelligence feeds?
- What is the domain age? (New domains higher risk)
- What is the hosting provider/ASN? (Cheap VPS, bulletproof hosting suspicious)
- What country is the destination located in? (Matches business operations?)

**Reputation Score Interpretation:**
- **Known Malicious (VirusTotal 10+/89):** Immediate escalation, likely active compromise
- **Suspicious (VirusTotal 3-9/89, new domain <30 days):** Continue investigation, elevated scrutiny
- **Unknown/Clean (VirusTotal 0-2/89, established domain):** Likely legitimate, verify business justification

**Decision Point:**
- If destination is **known malicious** → **Immediate escalation**
- If destination is **suspicious** → Continue investigation with elevated priority
- If destination is **unknown/clean** → Continue investigation, likely false positive

---

### Step 4: User Context Validation (1-2 minutes)

**Objective:** Identify which user account initiated the connection and assess legitimacy

**SPL Query - Correlate with Authentication Logs:**
```spl
index=ad sourcetype=WinEventLog:Security EventCode=4624
| search src_ip="<SOURCE_IP>"
| where _time >= <FIRST_SEEN_TIME> AND _time <= <LAST_SEEN_TIME>
| stats values(user) as users dc(user) as user_count by src_ip
| table src_ip users user_count
```

**SPL Query - Check User Role and Department:**
```spl
| inputlookup user_directory.csv
| search username="<USERNAME>"
| table username department job_title manager is_admin is_privileged
```

**Key Questions:**
- Is there a logged-in user associated with this connection?
- What is the user's role and department?
- Does the destination align with the user's job function?
  - IT admin accessing AWS/Azure = normal
  - Finance user accessing unknown hosting provider = suspicious
  - Developer accessing GitHub/npm = normal
  - Accounting user accessing port 22 SSH = suspicious

**Red Flags:**
- ❌ No associated user (connection without authentication = automated/malware)
- ❌ Service account with human-like behavior (service accounts shouldn't browse)
- ❌ Privileged account (Domain Admin, Enterprise Admin) initiating suspicious connections
- ❌ User role mismatched with destination (accounting user → SSH server)

**Decision Point:**
- If **no user context** and **suspicious destination** → **Escalate to HIGH priority**
- If **privileged account** with suspicious activity → **Immediate escalation**
- If **user role matches** destination type → Likely legitimate, verify business justification
- If **user role mismatches** → Suspicious, continue investigation

---

### Step 5: Behavioral Pattern Analysis (2-3 minutes)

**Objective:** Analyze connection timing, frequency, and data volume for malicious patterns

**SPL Query - Detailed Connection Timeline:**
```spl
index=network sourcetype=firewall action=allowed
| search src_ip="<SOURCE_IP>" dest_domain="<DEST_DOMAIN>" OR dest_ip="<DEST_IP>"
| bin _time span=1m
| stats count sum(bytes_out) as bytes_out sum(bytes_in) as bytes_in by _time src_ip dest_domain dest_port
| eval MB_out = round(bytes_out / 1048576, 2)
| eval MB_in = round(bytes_in / 1048576, 2)
| table _time count MB_out MB_in
| sort _time
```

**SPL Query - Calculate Connection Intervals (Beaconing Detection):**
```spl
index=network sourcetype=firewall action=allowed
| search src_ip="<SOURCE_IP>" dest_domain="<DEST_DOMAIN>" OR dest_ip="<DEST_IP>"
| sort _time
| streamstats current=f last(_time) as previous_time by src_ip dest_domain
| eval interval_seconds = _time - previous_time
| where isnotnull(interval_seconds)
| stats count avg(interval_seconds) as avg_interval stdev(interval_seconds) as stdev_interval values(interval_seconds) as all_intervals
| eval avg_interval_min = round(avg_interval / 60, 2)
| eval stdev_interval_min = round(stdev_interval / 60, 2)
| table count avg_interval_min stdev_interval_min all_intervals
```

**Beaconing Pattern Indicators:**
- **Regular intervals (low standard deviation):** 
  - 60 seconds (1 minute) → Common Cobalt Strike default
  - 300 seconds (5 minutes) → Common Metasploit default
  - 3600 seconds (1 hour) → Slower beaconing, APT-like
- **High connection count with consistent intervals:** Automated C2 communication
- **Very low standard deviation (<30 seconds):** Machine-driven, not human behavior

**Data Volume Analysis:**
- **Large uploads (>100MB):** Potential data exfiltration
- **Consistent small uploads/downloads:** C2 command/tasking traffic
- **Burst patterns:** Data staging or initial compromise download

**Time-of-Day Analysis:**
- **Off-hours activity (2 AM - 6 AM):** Suspicious if user not normally working
- **Business hours activity:** More likely legitimate
- **Weekend/holiday activity:** Suspicious if user not on-call

**Key Questions:**
- What is the average connection interval and standard deviation?
- Is the pattern regular (beaconing) or irregular (human-driven)?
- What is the total data volume uploaded vs. downloaded?
- When did the activity occur (business hours vs. off-hours)?

**Malicious Pattern Examples:**
- 287 connections with 5.01 minute average interval (stdev 0.23 min) = **HIGH CONFIDENCE C2 BEACON**
- 156 connections with 27.69 minute average interval (stdev 2.1 min) = **LIKELY C2 BEACON**
- 47 connections with 274 MB uploaded in 89 minutes = **LIKELY DATA EXFILTRATION**
- 1,247 connections irregular intervals (stdev 45 min) = **LIKELY LEGITIMATE (e.g., email sync)**

**Decision Point:**
- If **regular beaconing pattern** detected → **Escalate to HIGH/CRITICAL**
- If **large data upload** (>100MB) → **Escalate to HIGH priority**
- If **irregular pattern** with business justification → Likely legitimate

---

### Step 6: Endpoint Activity Correlation (2-3 minutes)

**Objective:** Correlate network connection with endpoint process activity to identify responsible application

**SPL Query - Sysmon Process Creation (Event ID 1):**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1
| search ComputerName="<SOURCE_HOSTNAME>" 
| where _time >= <FIRST_SEEN_TIME> AND _time <= <LAST_SEEN_TIME>
| table _time Image CommandLine ParentImage User IntegrityLevel
| sort _time
```

**SPL Query - Sysmon Network Connections (Event ID 3):**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=3
| search ComputerName="<SOURCE_HOSTNAME>" DestinationIp="<DEST_IP>" OR DestinationHostname="<DEST_DOMAIN>"
| table _time Image ProcessId DestinationIp DestinationPort User
| sort _time
```

**Key Questions:**
- What process initiated the network connection?
- Is the process a known legitimate application or suspicious executable?
- What is the process path? (C:\Program Files\ = likely legit, C:\Users\<user>\AppData\Local\Temp\ = suspicious)
- What was the parent process? (chrome.exe parent = user download, powershell.exe parent = script execution)
- What integrity level? (System = service, Medium = user, High = elevated)

**Suspicious Process Indicators:**
- ❌ Unsigned executables from Temp folders
- ❌ PowerShell/cmd.exe initiating external connections
- ❌ Renamed legitimate binaries (e.g., "chrome.exe" in wrong directory)
- ❌ calc.exe, notepad.exe, or other system utilities making network connections
- ❌ Processes with random naming (e.g., "a1b2c3d4.exe")

**Legitimate Process Examples:**
- ✅ chrome.exe, firefox.exe, msedge.exe (web browsers)
- ✅ outlook.exe (Office 365 email sync)
- ✅ OneDrive.exe (cloud storage sync)
- ✅ Teams.exe (Microsoft Teams)
- ✅ Code.exe (Visual Studio Code - developer workstation)

**Decision Point:**
- If **suspicious process** identified → **Escalate immediately**
- If **legitimate application** with business justification → Likely false positive
- If **no process attribution available** → Escalate based on previous indicators

---

### Step 7: Historical Pattern Analysis (1-2 minutes)

**Objective:** Determine if this is first-time behavior or established baseline activity

**SPL Query - Historical Connections to Same Destination:**
```spl
index=network sourcetype=firewall action=allowed
| search src_ip="<SOURCE_IP>" (dest_domain="<DEST_DOMAIN>" OR dest_ip="<DEST_IP>")
| where _time >= relative_time(now(), "-90d")
| bin _time span=1d
| stats count sum(bytes_out) as bytes_out by _time
| eval MB_out = round(bytes_out / 1048576, 2)
| table _time count MB_out
| sort _time
```

**SPL Query - Check If Destination Is Common Across Organization:**
```spl
index=network sourcetype=firewall action=allowed
| search (dest_domain="<DEST_DOMAIN>" OR dest_ip="<DEST_IP>")
| where _time >= relative_time(now(), "-30d")
| stats dc(src_ip) as unique_sources count sum(bytes_out) as total_bytes_out by dest_domain dest_port
| eval MB_out = round(total_bytes_out / 1048576, 2)
| table dest_domain dest_port unique_sources count MB_out
```

**Key Questions:**
- Is this the first time this source connected to this destination?
- Has this source connected to this destination regularly over the past 90 days?
- How many other internal systems connect to this destination?
- Is this a new service recently adopted by the organization?

**Interpretation:**
- **First-time connection + suspicious indicators** = HIGH RISK (potential compromise)
- **Established baseline (90 days of history)** = LOWER RISK (likely legitimate service)
- **Multiple sources organization-wide** = LIKELY LEGITIMATE (common service/SaaS)
- **Single source only** = ELEVATED RISK (targeted behavior)

**Decision Point:**
- If **first-time connection** with suspicious indicators → **Escalate**
- If **established baseline** with business justification → Whitelist candidate
- If **organization-wide usage** → Likely legitimate, add to cloud service whitelist

---

### Step 8: Final Disposition & Documentation (1-2 minutes)

**Objective:** Make final escalation decision and document investigation findings

**Escalation Decision Matrix:**

| Risk Score | Reputation | Beaconing | User Context | Disposition |
|------------|-----------|-----------|--------------|-------------|
| 10+ | Malicious | Yes | No user | **IMMEDIATE ESCALATION** |
| 10+ | Suspicious | Yes | Mismatch role | **IMMEDIATE ESCALATION** |
| 7-9 | Suspicious | Yes | Valid user | **ESCALATE - HIGH PRIORITY** |
| 7-9 | Clean | No | Valid user | **INVESTIGATE & CLOSE** |
| 4-6 | Clean | No | Valid user | **CLOSE - LIKELY LEGITIMATE** |

**Required Documentation (for escalated alerts):**

```
ALERT ID: <ALERT_ID>
SEVERITY: <CRITICAL/HIGH/MEDIUM>
ESCALATION TIME: <TIMESTAMP>
ANALYST: <YOUR NAME>

SOURCE ASSET:
- IP: <SOURCE_IP>
- Hostname: <SOURCE_HOSTNAME>
- Asset Type: <WORKSTATION/SERVER/ETC>
- Owner: <USER/DEPARTMENT>

DESTINATION:
- Domain/IP: <DEST_DOMAIN or DEST_IP>
- Port: <DEST_PORT>
- Reputation: <MALICIOUS/SUSPICIOUS/CLEAN>
- VirusTotal Score: <X/89>

BEHAVIORAL INDICATORS:
- Connection Count: <COUNT>
- Data Volume: <MB UPLOADED>
- Beaconing Pattern: <YES/NO - AVG INTERVAL>
- Time of Activity: <BUSINESS HOURS / OFF-HOURS>

USER CONTEXT:
- User Account: <USERNAME>
- Department/Role: <DEPARTMENT>
- Role Alignment: <MATCHES/MISMATCHES>

PROCESS ATTRIBUTION (if available):
- Process Name: <PROCESS.EXE>
- Process Path: <FULL_PATH>
- Parent Process: <PARENT.EXE>

INVESTIGATION SUMMARY:
<2-3 SENTENCE SUMMARY OF FINDINGS>

RECOMMENDED ACTION:
<ISOLATE ENDPOINT / DISABLE ACCOUNT / THREAT HUNT / ETC>
```

**For Closed Alerts (False Positives):**
- Document business justification
- Note if whitelist candidate
- Update cloud service whitelist if appropriate
- Provide feedback for detection tuning

---

## Investigation Examples

### Example 1: CRITICAL - Cobalt Strike C2 Beacon

**Alert Details:**
- Risk Score: 13 (CRITICAL)
- Source: 10.50.22.187 (DESKTOP-HR-045)
- Destination: 45.142.212.61 (direct IP, no domain)
- Port: 8888
- Connections: 287 over 23.9 hours
- Avg Interval: 5.01 minutes (stdev 0.23 min)
- Data Upload: 4.5 MB
- User: None (no associated authentication)

**Investigation Steps:**

**Step 1:** Alert is CRITICAL severity (13 points) - treat as active incident

**Step 2:** Asset identified as HR workstation, owner: Sarah Johnson (HR Manager)

**Step 3:** 
- VirusTotal: 45.142.212.61 = 12/89 vendors flag as malicious
- AbuseIPDB: 85% abuse confidence score (malware C2, port scan)
- WHOIS: Digital Ocean VPS, registered 3 weeks ago
- **VERDICT: KNOWN MALICIOUS**

**Step 4:** 
- No user authentication at time of connections
- Should have user Sarah Johnson logged in during business hours
- **RED FLAG: Connection without user session**

**Step 5:**
- Beaconing pattern: 287 connections, 5.01 min avg, 0.23 min stdev
- **HIGH CONFIDENCE C2 BEACON** (regular automated intervals)
- Activity started 3:47 AM (off-hours)
- Continued through business day

**Step 6:**
- Sysmon Event ID 3: Process = "svhost.exe" (note: typo, should be "svchost.exe")
- Process Path: C:\Users\sjohnson\AppData\Local\Temp\svhost.exe
- **RED FLAG: Misspelled system process in Temp folder**

**Step 7:**
- First connection to this IP occurred 3 days ago
- No other internal systems connect to this destination
- **RED FLAG: Isolated, new connection**

**Step 8 - DISPOSITION:**
- **IMMEDIATE ESCALATION TO IR TEAM**
- Endpoint isolated from network
- Account disabled pending IR investigation
- Memory capture initiated for forensics

**Investigation Time:** 4 minutes

---

### Example 2: HIGH - Data Exfiltration to Mega.nz

**Alert Details:**
- Risk Score: 11 (CRITICAL)
- Source: 10.50.18.93 (LAPTOP-FIN-078)
- Destination: g.api.mega.co.nz
- Port: 443 (HTTPS)
- Connections: 47 over 89 minutes
- Data Upload: 274 MB
- User: CORP\jthompson (Finance Analyst)

**Investigation Steps:**

**Step 1:** Alert is CRITICAL severity (11 points) - high priority investigation

**Step 2:** Asset identified as finance department laptop, owner: James Thompson

**Step 3:**
- VirusTotal: mega.co.nz = 0/89 (clean)
- Domain age: Established cloud storage service (legitimate company)
- **VERDICT: CLEAN REPUTATION (but unauthorized cloud storage)**

**Step 4:**
- User: James Thompson, Finance Analyst
- Department policy: Mega.nz NOT on approved cloud storage list
- Only OneDrive and SharePoint approved
- **POLICY VIOLATION: Unauthorized cloud storage usage**

**Step 5:**
- 47 connections over 89 minutes (avg 1.93 min intervals)
- 274 MB uploaded in single session
- Activity occurred 11:15 AM - 12:44 PM (business hours)
- **RED FLAG: Large data upload to unauthorized service**

**Step 6:**
- Sysmon Event ID 3: Process = "chrome.exe"
- User manually uploaded via web browser
- **User-initiated activity (not malware)**

**Step 7:**
- First time this user accessed Mega.nz
- No historical connections to this service
- **First-time use of unauthorized cloud storage**

**Step 8 - DISPOSITION:**
- **ESCALATE TO HIGH PRIORITY**
- Contact user and manager immediately
- Determine what data was uploaded
- Evaluate if insider threat or policy violation
- Review DLP logs for sensitive data classification
- Consider account suspension pending investigation

**Investigation Time:** 9 minutes

---

### Example 3: MEDIUM - Legitimate AWS CLI Usage (Developer)

**Alert Details:**
- Risk Score: 6 (MEDIUM)
- Source: 10.50.92.14 (DESKTOP-DEV-012)
- Destination: ec2.us-east-1.amazonaws.com
- Port: 443
- Connections: 83 over 45 minutes
- Data Upload: 18 MB
- User: CORP\mrodriguez (Senior Developer)

**Investigation Steps:**

**Step 1:** Alert is MEDIUM severity (6 points) - standard investigation

**Step 2:** Asset identified as developer workstation, owner: Maria Rodriguez

**Step 3:**
- Domain: ec2.us-east-1.amazonaws.com (AWS EC2 service)
- VirusTotal: 0/89 (clean)
- **VERDICT: LEGITIMATE AWS SERVICE**

**Step 4:**
- User: Maria Rodriguez, Senior Developer
- Department: Engineering
- Job function: Cloud infrastructure development
- **ROLE MATCHES ACTIVITY (developer using AWS)**

**Step 5:**
- 83 connections over 45 minutes (irregular intervals)
- Activity occurred 2:15 PM - 3:00 PM (business hours)
- Upload pattern consistent with API calls, not exfiltration
- **NORMAL DEVELOPER WORKFLOW**

**Step 6:**
- Sysmon Event ID 3: Process = "aws.exe" (AWS CLI tool)
- Process Path: C:\Program Files\Amazon\AWSCLIV2\aws.exe
- **LEGITIMATE AWS COMMAND LINE INTERFACE**

**Step 7:**
- User has connected to various AWS services daily for past 90 days
- Established baseline behavior
- Multiple developers in Engineering connect to AWS
- **ESTABLISHED LEGITIMATE USAGE**

**Step 8 - DISPOSITION:**
- **CLOSE AS FALSE POSITIVE**
- Document as legitimate developer activity
- Recommendation: Add ec2.*.amazonaws.com to cloud service whitelist
- Recommendation: Whitelist known developer workstations for AWS access

**Investigation Time:** 7 minutes

---

### Example 4: HIGH - SSH Backdoor to Residential IP

**Alert Details:**
- Risk Score: 10 (CRITICAL)
- Source: 10.50.31.44 (WEB-SERVER-03)
- Destination: 73.158.201.92 (direct IP)
- Port: 22 (SSH)
- Connections: 156 over 72 hours
- Data Upload: 18 MB
- User: None

**Investigation Steps:**

**Step 1:** Alert is CRITICAL severity (10 points) - treat as active incident

**Step 2:** 
- Asset: WEB-SERVER-03 (production web server)
- Asset Criticality: HIGH (public-facing application)
- **RED FLAG: Critical infrastructure affected**

**Step 3:**
- VirusTotal: 73.158.201.92 = 3/89 (low detection, but suspicious)
- WHOIS: Residential Comcast IP in Buffalo, NY
- ASN: Comcast Cable Communications (residential ISP)
- **VERDICT: SUSPICIOUS (residential IP, not datacenter)**

**Step 4:**
- No associated user authentication
- Web server should only have service account logins
- **RED FLAG: Automated connection without user context**

**Step 5:**
- 156 connections over 72 hours (avg 27.69 min intervals, stdev 2.1 min)
- **LIKELY C2 BEACON** (regular intervals, persistent over days)
- Activity occurred 24/7 including weekends
- **RED FLAG: Persistent automated activity**

**Step 6:**
- Server-side SSH client process making outbound connections
- SSH to residential IP (not typical for web server)
- **RED FLAG: Web server should not initiate outbound SSH**

**Step 7:**
- First connection to this IP occurred 72 hours ago
- No other internal systems connect to this destination
- **RED FLAG: Isolated, new connection from critical server**

**Step 8 - DISPOSITION:**
- **IMMEDIATE ESCALATION TO IR TEAM**
- Web server likely compromised with SSH backdoor
- Recommend immediate isolation pending forensics
- Check for web shell uploads, unauthorized file modifications
- Review web server access logs for initial compromise vector
- Threat hunt for lateral movement from this server

**Investigation Time:** 5 minutes

---

### Example 5: MEDIUM - False Positive (Zoom Video Conference)

**Alert Details:**
- Risk Score: 4 (MEDIUM)
- Source: 10.50.14.52 (LAPTOP-SALES-023)
- Destination: us04web.zoom.us
- Port: 443
- Connections: 94 over 63 minutes
- Data Upload: 45 MB
- User: CORP\djackson (Sales Director)

**Investigation Steps:**

**Step 1:** Alert is MEDIUM severity (4 points) - standard investigation

**Step 2:** Asset identified as sales laptop, owner: David Jackson

**Step 3:**
- Domain: us04web.zoom.us (Zoom video conferencing)
- VirusTotal: 0/89 (clean)
- **VERDICT: LEGITIMATE SERVICE**

**Step 4:**
- User: David Jackson, Sales Director
- Zoom is approved for business use
- **ROLE MATCHES ACTIVITY**

**Step 5:**
- 94 connections over 63 minutes (video conference duration)
- Upload volume consistent with video/audio stream
- Activity occurred 10:00 AM - 11:03 AM (business hours)
- **NORMAL VIDEO CONFERENCE PATTERN**

**Step 6:**
- Process: Zoom.exe
- Process Path: C:\Program Files\Zoom\bin\Zoom.exe
- **LEGITIMATE APPLICATION**

**Step 7:**
- User connects to Zoom daily for sales calls
- Dozens of employees connect to Zoom throughout day
- **ESTABLISHED ORGANIZATIONAL USAGE**

**Step 8 - DISPOSITION:**
- **CLOSE AS FALSE POSITIVE**
- Document as legitimate business communication
- Recommendation: Add *.zoom.us to cloud service whitelist
- Recommendation: Review why Zoom wasn't already whitelisted

**Investigation Time:** 6 minutes

---

## Common Pitfalls to Avoid

### Pitfall 1: Over-Reliance on Reputation Services
**Problem:** VirusTotal 0/89 doesn't guarantee legitimacy; newly registered domains may not be in threat feeds yet

**Solution:** Consider multiple factors (domain age, ASN, behavioral patterns, business justification) in addition to reputation scores

---

### Pitfall 2: Ignoring Business Context
**Problem:** Escalating legitimate developer activity or approved SaaS usage because it looks "suspicious"

**Solution:** Always correlate with user role, department, and business operations before escalating

---

### Pitfall 3: Missing Beaconing Patterns
**Problem:** Focusing only on connection count without analyzing timing intervals

**Solution:** Always calculate average interval and standard deviation to detect C2 beaconing

---

### Pitfall 4: Incomplete Process Attribution
**Problem:** Stopping investigation at network layer without correlating to endpoint process

**Solution:** Always query Sysmon Event ID 3 or EDR telemetry to identify responsible application

---

### Pitfall 5: Assuming Direct IPs Are Always Malicious
**Problem:** Legitimate services sometimes use direct IP connections (load balancers, CDNs)

**Solution:** Check ASN and hosting provider; datacenter IPs for known cloud providers can be legitimate

---

## Escalation Quick Reference

**IMMEDIATE ESCALATION (within 5 minutes):**
- Risk score 10+ with known malicious reputation
- Critical asset (DC, database, jump box) with suspicious connections
- Regular beaconing pattern (<5 min intervals, >100 connections) to unknown destination
- Large data upload (>100MB) to unauthorized cloud storage
- SSH/RDP connections from servers to residential IPs
- Privileged account initiating suspicious connections

**HIGH PRIORITY ESCALATION (within 15 minutes):**
- Risk score 7-9 with suspicious reputation
- First-time connection to high-risk TLD (.ru, .cn, .kp, .ir) without business justification
- Moderate data upload (50-100MB) to non-whitelisted destination
- Process attribution to suspicious executable (Temp folder, unsigned)
- User role mismatch (accounting user accessing SSH servers)

**INVESTIGATE & CLOSE:**
- Risk score 4-6 with clean reputation and business justification
- Established baseline activity (90 days of history)
- Legitimate application with valid user context
- Organization-wide service usage (not isolated to single host)
- Known false positive pattern with documented remediation

---

## Documentation Template

```
=== UNUSUAL NETWORK CONNECTION INVESTIGATION ===

ALERT METADATA:
- Alert ID: <ID>
- Risk Score: <SCORE>
- Severity: <CRITICAL/HIGH/MEDIUM/LOW>
- Detection Time: <TIMESTAMP>
- Analyst: <NAME>

SOURCE DETAILS:
- IP Address: <IP>
- Hostname: <HOSTNAME>
- Asset Type: <TYPE>
- Criticality: <LEVEL>
- Owner: <USER/DEPT>

DESTINATION DETAILS:
- Domain/IP: <DEST>
- Port: <PORT>
- Protocol: <PROTOCOL>
- Reputation Score: <SCORE>
- VirusTotal: <X/89>
- ASN/Hosting: <INFO>
- Country: <COUNTRY>

CONNECTION ANALYSIS:
- Connection Count: <COUNT>
- Duration: <DURATION>
- Avg Interval: <INTERVAL>
- Beaconing Detected: <YES/NO>
- Total Bytes Out: <BYTES>
- Total Bytes In: <BYTES>

USER CONTEXT:
- Associated User: <USERNAME>
- Department: <DEPT>
- Job Role: <ROLE>
- Role Alignment: <MATCHES/MISMATCHES>

PROCESS ATTRIBUTION:
- Process Name: <PROCESS>
- Process Path: <PATH>
- Parent Process: <PARENT>
- Signed: <YES/NO>

HISTORICAL ANALYSIS:
- First Seen: <DATE>
- Baseline Exists: <YES/NO>
- Organization-Wide Usage: <YES/NO>

INVESTIGATION FINDINGS:
<DETAILED SUMMARY>

DISPOSITION:
- Action Taken: <ESCALATE/CLOSE>
- Justification: <REASON>
- Recommendations: <SUGGESTIONS>

TIME SPENT: <MINUTES>
```

---

## Continuous Improvement

**Monthly Review Actions:**
1. Track investigation time per severity level - are we meeting SLAs?
2. Identify new false positive patterns requiring whitelist updates
3. Validate tuned detection still catching all true positives (zero false negatives)
4. Document new cloud services adopted by organization for whitelist
5. Review escalated cases - were escalations appropriate?
6. Gather analyst feedback on playbook clarity and effectiveness

**Metrics to Track:**
- Average investigation time by severity (target: <10 min for MEDIUM, <5 min for CRITICAL)
- False positive rate (target: <15%)
- True positive retention (target: 100%)
- Escalation accuracy (target: >90% of escalations are legitimate threats)
- Whitelist effectiveness (alerts prevented vs. coverage maintained)

---

**Last Updated:** December 2024  
**Playbook Version:** 1.0  
**Author:** SOC Detection Engineering Team
