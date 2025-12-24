# Escalation Criteria: Unusual Network Connections

## Purpose
This document defines clear escalation criteria for the Unusual Network Connections detection to ensure consistent, accurate decision-making across the SOC team. The goal is to escalate genuine threats rapidly while closing false positives efficiently without wasting IR team capacity.

---

## Escalation Tiers

### Tier 1: IMMEDIATE ESCALATION (within 5 minutes)
**Severity:** CRITICAL  
**Action:** Immediate IR team notification, potential endpoint isolation  
**SLA:** Escalate within 5 minutes of alert triage completion

### Tier 2: HIGH PRIORITY ESCALATION (within 15 minutes)
**Severity:** HIGH  
**Action:** Standard escalation to IR team after validation  
**SLA:** Escalate within 15 minutes of alert triage completion

### Tier 3: MEDIUM PRIORITY ESCALATION (within 1 hour)
**Severity:** MEDIUM  
**Action:** Document findings, escalate if additional suspicious indicators found  
**SLA:** Complete investigation within 1 hour, escalate if warranted

### Tier 4: LOW PRIORITY / CLOSE (no escalation)
**Severity:** LOW  
**Action:** Close as false positive, document for tuning  
**SLA:** Close within 15 minutes with proper documentation

---

## Tier 1: IMMEDIATE ESCALATION Conditions

### Condition 1: Known Malicious Infrastructure
**Trigger:**
- Destination IP/domain flagged by threat intelligence feeds
- VirusTotal detection ratio ≥10/89 vendors
- AbuseIPDB confidence score ≥75%
- Listed in internal threat intel IOC database

**Why This Matters:**
Known malicious infrastructure indicates active compromise or attack in progress. Any connection to confirmed C2 servers, malware download sites, or phishing infrastructure requires immediate response.

**Example:**
```
Source: 10.50.22.187 (HR workstation)
Destination: 45.142.212.61
VirusTotal: 12/89 (Malware C2, Trojan downloader)
Risk Score: 13 (CRITICAL)
→ IMMEDIATE ESCALATION
```

**Response Actions:**
- Isolate endpoint from network immediately
- Capture memory dump for forensics
- Disable associated user account
- Check for lateral movement from compromised host
- Initiate full incident response procedures

---

### Condition 2: High-Confidence C2 Beaconing Pattern
**Trigger:**
- ≥100 connections with average interval <5 minutes
- Standard deviation of intervals <30 seconds (highly regular)
- Persistent activity over ≥12 hours
- No associated user authentication (automated behavior)

**Why This Matters:**
Regular beaconing with machine-precision timing is the hallmark of automated C2 communication. Human behavior is never this consistent. This indicates active malware communicating with attacker infrastructure.

**Example:**
```
Source: 10.50.31.44 (web server)
Destination: 73.158.201.92 (residential IP)
Connections: 287 over 23.9 hours
Avg Interval: 5.01 minutes (stdev 0.23 min)
Risk Score: 13 (CRITICAL)
→ IMMEDIATE ESCALATION
```

**Response Actions:**
- Isolate system immediately
- Block destination IP/domain at perimeter firewall
- Capture network traffic for C2 protocol analysis
- Check for data exfiltration or lateral movement
- Forensic analysis of compromised endpoint

---

### Condition 3: Critical Asset with Suspicious Activity
**Trigger:**
- Source asset is Domain Controller, database server, jump box, or critical infrastructure
- Any connection to non-whitelisted external destination
- Risk score ≥7 (HIGH or CRITICAL)

**Why This Matters:**
Critical infrastructure should have highly predictable, tightly controlled network patterns. Any deviation from baseline on these systems represents severe risk and potential compromise of crown jewel assets.

**Example:**
```
Source: DC01.corp.local (Domain Controller)
Destination: unknown-cloud-service.com
Port: 443
Risk Score: 8 (HIGH)
→ IMMEDIATE ESCALATION (even though risk score <10, DC involvement escalates priority)
```

**Response Actions:**
- Do NOT isolate Domain Controller without consulting IR lead
- Immediately notify IR team and senior management
- Capture network traffic and memory if safe to do so
- Check for Golden Ticket attacks, DCSync, or credential dumping
- Review all AD changes and privileged account activity

---

### Condition 4: Large Data Exfiltration (>100MB)
**Trigger:**
- Total bytes_out >100MB in single session
- Destination not on approved cloud storage whitelist
- Upload occurred to suspicious or unknown hosting provider
- Risk score ≥10 (CRITICAL)

**Why This Matters:**
Large data uploads to unauthorized destinations represent potential intellectual property theft, customer data breach, or compromise of sensitive business information. Financial and regulatory impact can be severe.

**Example:**
```
Source: 10.50.18.93 (Finance laptop)
Destination: g.api.mega.co.nz (unauthorized cloud storage)
Upload: 274 MB in 89 minutes
User: CORP\jthompson (Finance Analyst)
Risk Score: 11 (CRITICAL)
→ IMMEDIATE ESCALATION
```

**Response Actions:**
- Contact user and manager immediately
- Determine what data was uploaded (file names, classifications)
- Check DLP logs for sensitive data detection
- Disable account pending investigation
- Legal/compliance notification if PII/PCI/PHI involved
- Attempt to retrieve data from cloud service if possible

---

### Condition 5: Privileged Account Initiating Suspicious Connections
**Trigger:**
- User account is Domain Admin, Enterprise Admin, or other privileged role
- Connection to non-whitelisted destination
- Any suspicious indicators (direct IP, unusual port, high-risk TLD)
- Risk score ≥7 (HIGH or CRITICAL)

**Why This Matters:**
Privileged accounts represent "keys to the kingdom." If compromised, attackers have full access to entire environment. Any anomalous behavior from these accounts must be treated as potential breach.

**Example:**
```
Source: 10.50.7.22 (IT Admin workstation)
User: CORP\domain_admin
Destination: 192.168.45.88 (direct IP, unknown)
Port: 4444 (Metasploit default)
Risk Score: 10 (CRITICAL)
→ IMMEDIATE ESCALATION
```

**Response Actions:**
- Disable privileged account immediately
- Reset passwords for all privileged accounts as precaution
- Check for unauthorized AD changes, group membership modifications
- Review all system access by this account in past 30 days
- Threat hunt for lateral movement using these credentials

---

### Condition 6: Process Attribution to Malicious Executable
**Trigger:**
- Sysmon/EDR identifies process in suspicious location (Temp, AppData\Local\Temp, Downloads)
- Unsigned or renamed legitimate binary (e.g., "chrome.exe" in wrong path)
- Process name matches known malware families (svhost.exe typo, conhost.exe in wrong location)
- Known malicious hash from threat intelligence

**Why This Matters:**
Process-level attribution definitively identifies malware execution. Combined with network activity, this confirms active compromise requiring immediate response.

**Example:**
```
Source: 10.50.22.187 (workstation)
Destination: 45.142.212.61
Process: C:\Users\user\AppData\Local\Temp\svhost.exe (typo in "svchost")
Unsigned: Yes
Risk Score: 13 (CRITICAL)
→ IMMEDIATE ESCALATION
```

**Response Actions:**
- Isolate endpoint immediately
- Submit executable hash to VirusTotal and internal sandbox
- Capture file for malware analysis
- Check for persistence mechanisms (registry, scheduled tasks)
- Hunt for same hash across environment

---

## Tier 2: HIGH PRIORITY ESCALATION Conditions

### Condition 7: Moderate Data Upload to Suspicious Destination
**Trigger:**
- Total bytes_out 50-100MB
- Destination has suspicious reputation (VirusTotal 3-9/89) or newly registered domain (<30 days)
- No clear business justification
- Risk score 7-9 (HIGH)

**Why This Matters:**
While not as severe as >100MB uploads, 50-100MB represents significant data volume that could contain sensitive information. Suspicious destination elevates concern.

**Example:**
```
Source: 10.50.42.19 (Marketing laptop)
Destination: file-share-2024.xyz (registered 18 days ago)
Upload: 78 MB
VirusTotal: 4/89 (suspicious file hosting)
Risk Score: 8 (HIGH)
→ HIGH PRIORITY ESCALATION
```

**Response Actions:**
- Contact user to determine what was uploaded and why
- Check user's recent file access logs
- Review DLP alerts for this user
- Validate business justification with manager
- Escalate to IR if cannot confirm legitimate business purpose

---

### Condition 8: Regular Beaconing Without High Confidence
**Trigger:**
- ≥50 connections with average interval 5-10 minutes
- Standard deviation <2 minutes (fairly regular)
- Activity over ≥6 hours
- Risk score 7-9 (HIGH)

**Why This Matters:**
Less aggressive beaconing patterns may indicate slower C2 communication or legitimate automation. Requires validation but likely represents automated behavior requiring investigation.

**Example:**
```
Source: 10.50.31.44 (web server)
Destination: update-service.tk (suspicious free TLD)
Connections: 78 over 8.5 hours
Avg Interval: 6.5 minutes (stdev 1.2 min)
Risk Score: 8 (HIGH)
→ HIGH PRIORITY ESCALATION
```

**Response Actions:**
- Review web server logs for unauthorized modifications
- Check for web shells or backdoor code
- Validate legitimate scheduled tasks/cron jobs
- Capture network traffic for protocol analysis
- Escalate to IR if cannot confirm legitimate automation

---

### Condition 9: Connection to High-Risk Geographic Locations
**Trigger:**
- Destination in high-risk country (.ru, .cn, .kp, .ir TLDs or geoIP)
- No documented business operations or approved vendors in that country
- Risk score 7-9 (HIGH)
- User role doesn't justify international connections

**Why This Matters:**
Connections to certain countries are frequently associated with APT groups, state-sponsored actors, and cybercrime organizations. Without business justification, these represent elevated risk.

**Example:**
```
Source: 10.50.18.93 (HR workstation)
Destination: file-storage.ru
Country: Russia
User: HR Coordinator (no international responsibilities)
Risk Score: 9 (HIGH)
→ HIGH PRIORITY ESCALATION
```

**Response Actions:**
- Verify with user and manager if legitimate business need
- Check company travel records (user recently travel internationally?)
- Review geopolitical threat intelligence for current campaigns
- Escalate to IR if no business justification

---

### Condition 10: SSH/RDP from Unexpected Assets
**Trigger:**
- SSH (port 22) or RDP (port 3389) connection to external destination
- Source asset is NOT an authorized jump box, bastion host, or IT admin workstation
- Destination is residential IP or cheap VPS provider
- Risk score 7-9 (HIGH)

**Why This Matters:**
SSH and RDP should only originate from controlled administrative infrastructure. Workstations and servers making outbound SSH/RDP connections often indicate backdoors or unauthorized remote access.

**Example:**
```
Source: WEB-SERVER-03 (production web server)
Destination: 73.158.201.92 (Comcast residential)
Port: 22 (SSH)
Risk Score: 10 (CRITICAL - but HIGH escalation due to need for validation)
→ HIGH PRIORITY ESCALATION
```

**Response Actions:**
- Verify if system administrator made connection (check with IT team)
- Review SSH configuration for unauthorized keys
- Check for reverse SSH tunnels or backdoors
- Escalate to IR if unauthorized

---

### Condition 11: User Role Mismatch
**Trigger:**
- User's job function doesn't align with destination type
- Finance/HR/Legal accessing developer tools (GitHub, AWS)
- Non-IT staff accessing SSH servers or cloud infrastructure
- Risk score 7-9 (HIGH)

**Why This Matters:**
Compromised accounts are often detected by behavioral anomalies. Attackers use stolen credentials to access resources the legitimate user would never touch.

**Example:**
```
Source: 10.50.18.93 (Finance laptop)
User: CORP\accountant (Accounting Manager)
Destination: aws.console.amazon.com
Activity: EC2 instance creation attempts
Risk Score: 8 (HIGH)
→ HIGH PRIORITY ESCALATION
```

**Response Actions:**
- Contact user immediately to verify activity
- Check for recent phishing attempts targeting this user
- Review recent password changes or account activity
- Disable account if user doesn't recognize activity
- Check for lateral movement or privilege escalation

---

### Condition 12: First-Time Connection to Suspicious Infrastructure
**Trigger:**
- No historical connections (90-day lookback) to this destination
- Destination has medium reputation score (VirusTotal 3-6/89)
- Risk score 7-9 (HIGH)
- Only one or few internal hosts connecting (not organization-wide)

**Why This Matters:**
First-time connections to suspicious infrastructure represent potential initial compromise or reconnaissance. Established baselines suggest legitimacy; first-time activity requires validation.

**Example:**
```
Source: 10.50.42.19 (Marketing workstation)
Destination: cloud-files.tk (free TLD, registered 45 days ago)
First Seen: Today (no previous connections in 90 days)
VirusTotal: 5/89
Risk Score: 7 (HIGH)
→ HIGH PRIORITY ESCALATION
```

**Response Actions:**
- Contact user to determine business purpose
- Check if new SaaS tool recently adopted by company
- Review procurement/IT approval records
- Validate with user's manager
- Close if legitimate new service, escalate if suspicious

---

## Tier 3: MEDIUM PRIORITY ESCALATION (Investigate Then Decide)

### Condition 13: Moderate Risk Score with Clean Reputation
**Trigger:**
- Risk score 4-6 (MEDIUM)
- Destination has clean reputation (VirusTotal 0-2/89)
- Established domain (>1 year old)
- Some suspicious indicators but not high confidence

**Why This Matters:**
Medium-risk alerts require investigation to determine if legitimate business activity or actual threat. Many will be false positives, but some may reveal policy violations or shadow IT.

**Investigation Approach:**
1. Verify user context and job role
2. Check for business justification
3. Review historical connection patterns
4. Validate with user if ambiguous

**Possible Outcomes:**
- Legitimate business activity → Close as false positive, consider whitelist
- Unauthorized but benign (shadow IT) → Policy violation, notify management
- Suspicious activity → Escalate to HIGH priority
- Cannot determine → Escalate for deeper investigation

---

### Condition 14: Non-Standard Ports Without High Risk Indicators
**Trigger:**
- Connection on unusual port (not 80, 443, 22, 3389, etc.)
- Destination has clean reputation
- User context available and role makes sense
- Risk score 4-6 (MEDIUM)

**Example:**
```
Source: 10.50.92.14 (Developer workstation)
User: CORP\dev_engineer
Destination: build-server.company-vendor.com
Port: 8080 (HTTP alternate)
Risk Score: 5 (MEDIUM)
→ INVESTIGATE: Likely legitimate but non-standard port requires validation
```

**Investigation Approach:**
- Verify if this is approved vendor or service
- Check with user about business purpose
- Validate connection is HTTPS (encrypted) not HTTP (plaintext)
- Close if legitimate development/vendor connection

---

### Condition 15: Long Domain Names (Potential DNS Tunneling)
**Trigger:**
- Domain name length >50 characters
- No other high-risk indicators
- Risk score 4-6 (MEDIUM)

**Why This Matters:**
DNS tunneling uses excessively long subdomain queries to exfiltrate data. However, some CDNs and cloud services legitimately use long domain names.

**Example:**
```
Destination: very-long-cloudfront-distribution-name-for-cdn-content.cloudfront.net (68 characters)
Risk Score: 4 (MEDIUM)
→ INVESTIGATE: Likely CloudFront CDN, but verify
```

**Investigation Approach:**
- Check if domain belongs to known CDN (CloudFront, Akamai)
- Review DNS query patterns (many short queries vs. few long queries)
- Analyze subdomain randomness (random strings suggest tunneling)
- Close if legitimate CDN, escalate if true tunneling detected

---

## Tier 4: LOW PRIORITY / CLOSE (No Escalation Required)

### Condition 16: Established Baseline with Business Justification
**Trigger:**
- Historical connections over 90 days
- Organization-wide usage (multiple hosts connect to same destination)
- Clean reputation (VirusTotal 0/89)
- Risk score 1-3 (LOW)

**Why Close:**
Established baseline with broad organizational usage indicates legitimate business service that should have been whitelisted already.

**Action:**
- Close as false positive
- Document business justification
- Recommend adding to cloud service whitelist
- Update detection tuning to prevent future alerts

---

### Condition 17: Known Developer Tools and Services
**Trigger:**
- Destination is GitHub, npm, PyPI, Docker Hub, Maven Central
- Source is developer workstation or build server
- User has developer role
- Risk score 1-3 (LOW)

**Why Close:**
Standard developer workflow - downloading code, packages, container images is expected behavior from development teams.

**Action:**
- Close as false positive
- Verify destination is actually legitimate service (not typosquatted domain)
- Recommend adding to whitelist if not already present

---

### Condition 18: Legitimate SaaS with User Context
**Trigger:**
- Destination is known SaaS application (Salesforce, Workday, ServiceNow)
- User role aligns with application (sales using Salesforce, HR using Workday)
- Activity during business hours
- Risk score 1-3 (LOW)

**Why Close:**
Normal business operations using approved enterprise applications.

**Action:**
- Close as false positive
- Verify SaaS application is on approved vendor list
- If not on approved list but widely used, notify IT/procurement
- Add to whitelist to prevent future alerts

---

## Special Escalation Scenarios

### Scenario A: Impossible Travel / Geographic Anomaly
**Trigger:**
- User authenticates from Location A
- Within <2 hours, same user initiates connections from Location B (>500 miles away)
- Risk score may be LOW, but geographic impossibility overrides

**Why Escalate:**
Physical impossibility of travel indicates credential theft or account compromise.

**Action:**
- IMMEDIATE ESCALATION regardless of risk score
- Disable user account pending investigation
- Reset password and revoke active sessions
- Investigate compromise vector (phishing, credential stuffing)

---

### Scenario B: Off-Hours Activity from Non-IT Accounts
**Trigger:**
- Activity between 11 PM - 6 AM local time
- User is not IT staff or on-call rotation
- Destination is suspicious or unknown
- Risk score ≥4 (MEDIUM or higher)

**Why Escalate:**
Off-hours activity from non-IT accounts may indicate compromised credentials being used by attackers in different time zones.

**Action:**
- HIGH PRIORITY ESCALATION
- Contact user to verify if they were actually working
- Check for VPN connections from unusual geographic locations
- Validate business justification or escalate for compromise investigation

---

### Scenario C: Multiple Hosts to Same Suspicious Destination
**Trigger:**
- ≥5 different internal hosts connecting to same suspicious destination
- Destination has medium/suspicious reputation
- Connections started around same time (within 24 hours)
- Risk score ≥7 per host (HIGH)

**Why Escalate:**
Widespread connections suggest worm propagation, mass phishing campaign success, or coordinated attack across organization.

**Action:**
- IMMEDIATE ESCALATION
- Treat as potential outbreak or coordinated breach
- Block destination at firewall immediately
- Isolate all affected hosts
- Initiate organization-wide threat hunt

---

### Scenario D: Tor Exit Node Connections
**Trigger:**
- Destination IP is known Tor exit node
- No documented business need for Tor usage
- Risk score ≥7 (HIGH)

**Why Escalate:**
Tor usage in enterprise environment typically violates acceptable use policy and may indicate data exfiltration, insider threat, or malware using Tor for anonymity.

**Action:**
- HIGH PRIORITY ESCALATION
- Block Tor exit nodes at firewall
- Contact user and manager immediately
- Investigate business justification (researchers, privacy advocates may have legitimate need)
- Escalate to IR if unauthorized

---

### Scenario E: Lateral Movement Pattern
**Trigger:**
- Single source IP connecting to multiple unusual external destinations within short timeframe
- Destinations span different ASNs, countries, and service types
- Risk score individually may be MEDIUM, but pattern escalates priority
- Activity suggests reconnaissance or C2 failover

**Why Escalate:**
Shotgun approach to external connections suggests attacker trying multiple C2 channels or scanning for available infrastructure.

**Action:**
- HIGH PRIORITY ESCALATION
- Isolate source host immediately
- Review all network connections in past 24 hours
- Check for indicators of initial compromise
- Threat hunt for lateral movement from this host

---

## Escalation Decision Flowchart

```
START: Alert Triggered
    |
    v
Is destination known malicious? (VirusTotal ≥10/89)
    |
    YES → IMMEDIATE ESCALATION (Tier 1)
    |
    NO
    v
Is source asset critical infrastructure? (DC, DB, Jump Box)
    |
    YES → IMMEDIATE ESCALATION (Tier 1)
    |
    NO
    v
Is there C2 beaconing? (≥100 conn, <5 min avg, <30s stdev)
    |
    YES → IMMEDIATE ESCALATION (Tier 1)
    |
    NO
    v
Is data upload >100MB to unauthorized destination?
    |
    YES → IMMEDIATE ESCALATION (Tier 1)
    |
    NO
    v
Is risk score ≥10? (CRITICAL severity)
    |
    YES → IMMEDIATE ESCALATION (Tier 1)
    |
    NO
    v
Is risk score 7-9? (HIGH severity)
    |
    YES → HIGH PRIORITY ESCALATION (Tier 2)
    |
    NO
    v
Is risk score 4-6? (MEDIUM severity)
    |
    YES → INVESTIGATE THOROUGHLY (Tier 3)
        |
        v
        Can you confirm legitimate business purpose?
            |
            YES → CLOSE as false positive, document
            |
            NO → ESCALATE to HIGH PRIORITY
    |
    NO (risk score 1-3, LOW severity)
    v
Does destination have established baseline? (90 days history)
    |
    YES → CLOSE as false positive, consider whitelist
    |
    NO → INVESTIGATE briefly, likely false positive
```

---

## Escalation Documentation Requirements

### For IMMEDIATE ESCALATION (Tier 1):
**Required Information:**
- Alert ID and detection time
- Source IP, hostname, asset type, criticality
- Destination IP/domain, reputation scores, hosting details
- Risk score and specific indicators that triggered escalation
- Beaconing analysis (if applicable)
- Data volume uploaded/downloaded
- User context (or lack thereof)
- Process attribution (if available from EDR)
- Recommended immediate actions (isolation, account disable, etc.)

### For HIGH PRIORITY ESCALATION (Tier 2):
**Required Information:**
- All information from Tier 1
- Business context investigation results
- User validation attempts (contacted user? response?)
- Historical pattern analysis
- Similar activity across organization?
- Recommended investigation priorities

### For CLOSED ALERTS (Tier 4):
**Required Information:**
- Alert ID
- Disposition reason (established baseline, legitimate SaaS, developer tool, etc.)
- Business justification documented
- Whitelist recommendation (yes/no)
- Feedback for detection tuning

---

## Analyst Training Notes

### Common Escalation Mistakes to Avoid:

**Mistake #1: Over-Escalating Legitimate Cloud Services**
- Problem: Treating every AWS/Azure connection as suspicious
- Solution: Understand business operations, validate user roles, check organizational usage

**Mistake #2: Under-Escalating Due to Clean Reputation**
- Problem: Trusting VirusTotal 0/89 without additional validation
- Solution: Consider behavioral patterns, beaconing, data volume regardless of reputation

**Mistake #3: Missing Beaconing Patterns**
- Problem: Focusing only on risk score without analyzing connection intervals
- Solution: Always calculate average interval and standard deviation for high-volume connections

**Mistake #4: Ignoring User Context**
- Problem: Escalating activity that aligns with user's job function
- Solution: Correlate with AD authentication, check user role and department

**Mistake #5: Inconsistent Escalation Standards**
- Problem: Different analysts escalating similar scenarios differently
- Solution: Follow this documented criteria consistently, discuss edge cases in team meetings

---

## Monthly Review Process

**Review Metrics:**
1. **Escalation Accuracy:** What percentage of escalations were confirmed threats?
   - Target: ≥85% of Tier 1/2 escalations are legitimate threats
2. **Missed Threats:** Were any incidents missed due to failure to escalate?
   - Target: Zero missed threats (100% true positive escalation)
3. **False Escalations:** How many escalations were determined to be false positives?
   - Track reasons and update criteria to prevent recurrence
4. **Escalation Consistency:** Are different analysts escalating similar scenarios consistently?
   - Review sample of closed and escalated alerts across team

**Continuous Improvement Actions:**
- Update escalation criteria based on new attack patterns
- Add new special scenarios as discovered
- Refine decision thresholds based on operational experience
- Train analysts on common mistakes and edge cases
- Update whitelist to reduce legitimate activity being investigated

---

## Quick Reference Card (Print and Post at Analyst Desks)

```
╔════════════════════════════════════════════════════════════════╗
║          UNUSUAL NETWORK CONNECTIONS - ESCALATION              ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  IMMEDIATE ESCALATION (Tier 1 - <5 min):                      ║
║  • VirusTotal ≥10/89 (known malicious)                        ║
║  • C2 beaconing (≥100 conn, <5min avg, <30s stdev)            ║
║  • Critical asset (DC, database, jump box)                    ║
║  • Data exfiltration >100MB                                   ║
║  • Privileged account + suspicious activity                    ║
║  • Risk score ≥10 (CRITICAL)                                  ║
║                                                                ║
║  HIGH PRIORITY ESCALATION (Tier 2 - <15 min):                 ║
║  • Risk score 7-9 (HIGH severity)                             ║
║  • Data upload 50-100MB                                       ║
║  • Beaconing (≥50 conn, 5-10min avg)                          ║
║  • High-risk TLD (.ru, .cn, .kp, .ir)                         ║
║  • SSH/RDP from unexpected assets                             ║
║  • User role mismatch                                         ║
║                                                                ║
║  INVESTIGATE (Tier 3 - <1 hour):                              ║
║  • Risk score 4-6 (MEDIUM severity)                           ║
║  • Clean reputation but unusual indicators                     ║
║  • Verify business justification                              ║
║  • Escalate if cannot confirm legitimate                       ║
║                                                                ║
║  CLOSE (Tier 4):                                              ║
║  • Risk score 1-3 (LOW severity)                              ║
║  • Established 90-day baseline                                ║
║  • Org-wide usage (multiple hosts)                            ║
║  • Known SaaS with user context                               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
```

---

**Last Updated:** December 2024  
**Document Version:** 1.0  
**Author:** SOC Detection Engineering Team
