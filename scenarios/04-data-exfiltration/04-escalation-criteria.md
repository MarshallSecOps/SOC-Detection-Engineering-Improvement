# Data Exfiltration Detection - Escalation Criteria

## Overview

This document provides clear escalation criteria for data exfiltration alerts. The goal is to ensure **consistent, accurate escalation decisions** across the SOC team while preventing both under-escalation (missing real threats) and over-escalation (wasting IR team resources).

**Key Principle:** Risk score provides initial prioritization, but **context determines disposition**. A CRITICAL alert may be legitimate (approved backup), and a MEDIUM alert may be malicious (insider threat with clever obfuscation).

---

## Escalation Tiers

### Tier 1: IMMEDIATE ESCALATION (Within 15 Minutes)

**When to Use:**
- **Critical business impact** - Sensitive data (PII/PCI/PHI/CONFIDENTIAL) to unauthorized destination
- **Active insider threat** - Terminated/resigned employee, disciplinary action in progress
- **Confirmed account compromise** - Impossible travel, malware detected, phishing correlation
- **Attacker-favored infrastructure** - Anonymous file sharing services with any sensitive data
- **Extreme anomaly** - >3σ baseline deviation + unauthorized service + sensitive data

**Escalation Path:**
1. **Immediately notify IR team** (Slack: #incident-response, Email: ir-team@company.com)
2. **Document in SIEM** with "IMMEDIATE ESCALATION" tag
3. **Do NOT contact user** (may alert insider threat or compromised account)
4. **Prepare summary** for IR team handoff (1-2 sentence alert description)

**Examples:**

**Example 1: PII to Anonymous File Sharing**
```
Alert: Finance user uploaded 487MB containing 2,847 PII/PCI records to Mega.nz at 2 AM Sunday
Risk Score: 19 (CRITICAL)
Escalation Reason: Anonymous service + PII/PCI + off-hours + resigned employee
Action: IMMEDIATE escalation - disable account, contact IR + Legal
```

**Example 2: Compromised Account Exfiltration**
```
Alert: Marketing user uploaded 215MB PROPRIETARY docs to personal Dropbox at 3 AM
Risk Score: 13 (CRITICAL)
Investigation: 237 failed logins from Russian IP, impossible travel detected, recent phishing click
Escalation Reason: Confirmed account compromise + data exfiltration in progress
Action: IMMEDIATE escalation - disable account, block IP, reset credentials
```

**Example 3: Terminated Employee Data Theft**
```
Alert: Engineering user uploaded 1.2GB source code to personal Google Drive
Risk Score: 14 (CRITICAL)
Investigation: Employee gave notice yesterday, uploading company IP to personal account
Escalation Reason: Insider threat - pre-resignation data theft
Action: IMMEDIATE escalation - disable account, contact Legal for potential criminal charges
```

---

### Tier 2: HIGH PRIORITY ESCALATION (Within 1 Hour)

**When to Use:**
- **Policy violation** - Large uploads to unapproved personal cloud accounts
- **Moderate sensitive data** - INTERNAL/PROPRIETARY to non-whitelisted services
- **High-risk department anomaly** - Finance/Legal/HR uploading to personal cloud storage
- **Suspicious but not confirmed** - Multiple indicators but business justification possible
- **Off-hours activity without clear justification**

**Escalation Path:**
1. **Complete investigation** (8-12 minutes)
2. **Contact user's manager** for business justification validation
3. **Escalate to SOC Lead** if no justification or manager unavailable
4. **Document findings** in SIEM with manager response

**Examples:**

**Example 1: High-Risk Department to Personal Cloud**
```
Alert: HR user uploaded 92MB to personal Dropbox containing employee records (PII)
Risk Score: 8 (HIGH)
Investigation: Dropbox personal account, not business tier, HR user with PII access
Escalation Reason: High-risk department + PII + personal account requires validation
Action: Contact HR manager - if no business justification, escalate to IR
```

**Example 2: Large Upload to Unapproved Service**
```
Alert: Sales user uploaded 340MB to WeTransfer
Risk Score: 6 (MEDIUM)
Investigation: PUBLIC data (product demos), but WeTransfer not on approved list
Escalation Reason: Shadow IT - requires policy validation
Action: Contact manager - confirmed legitimate customer demo, update policy to approve WeTransfer
```

**Example 3: Off-Hours Unexplained Upload**
```
Alert: Accounting user uploaded 178MB to Box.com at 11 PM Saturday
Risk Score: 9 (HIGH)
Investigation: Box Business tier, INTERNAL classification, user normally works M-F 9-5
Escalation Reason: Off-hours + high-risk department + atypical behavior
Action: Contact manager Monday morning - if no justification, escalate for insider threat review
```

---

### Tier 3: MEDIUM PRIORITY - INVESTIGATE THOROUGHLY

**When to Use:**
- **First-time service usage** - User uploading to cloud service for the first time
- **Moderate baseline deviation** - 2-3σ deviation requiring context validation
- **Shadow IT scenarios** - Unapproved but potentially legitimate SaaS adoption
- **BYOD/personal device uploads** - Personal cloud storage from BYOD devices
- **Borderline risk scores** - Risk score 5-7 requiring detailed analysis

**Escalation Path:**
1. **Thorough investigation** (15-20 minutes)
2. **Validate business justification** with user or manager
3. **Check IT service catalog** for approved/pending services
4. **Document findings** and recommendation (approve vs. escalate)
5. **Escalate if no justification** or policy violation confirmed

**Examples:**

**Example 1: First-Time Service Usage**
```
Alert: Developer uploaded 95MB to new code repository service
Risk Score: 6 (MEDIUM)
Investigation: First time using this service, INTERNAL code, new SaaS tool
Action: Contact developer - confirmed trial of new CI/CD platform, escalate to IT for procurement approval
```

**Example 2: Shadow IT Legitimate Need**
```
Alert: Marketing uploaded 250MB to Canva.com (design tool)
Risk Score: 5 (MEDIUM)
Investigation: First time using Canva, PUBLIC marketing materials
Action: Contact manager - confirmed legitimate design work, submit to IT for SaaS approval process
```

**Example 3: BYOD Personal Cloud Sync**
```
Alert: Remote employee uploaded 120MB to personal OneDrive from home
Risk Score: 7 (HIGH)
Investigation: BYOD laptop, work-from-home user, INTERNAL documents
Action: Validate BYOD policy compliance, check if personal OneDrive approved for BYOD, document
```

---

### Tier 4: CLOSE - APPROVED ACTIVITY

**When to Use:**
- **Approved corporate services** - OneDrive/SharePoint, Google Workspace, Dropbox Business with proper authorization
- **Service accounts** - Automated backups to approved cloud storage
- **Public data classification** - No sensitive data detected by DLP
- **Normal user behavior** - Within baseline, consistent with job function
- **Manager-approved exceptions** - Business justification documented and approved

**Escalation Path:**
1. **Document closure rationale** (2-3 sentences)
2. **Tag in SIEM** as "CLOSED - APPROVED ACTIVITY"
3. **Recommend tuning** if similar FPs expected
4. **No escalation required**

**Examples:**

**Example 1: Corporate OneDrive Sync**
```
Alert: User uploaded 324MB to OneDrive
Risk Score: 5 (MEDIUM - triggered due to volume)
Investigation: Corporate OneDrive (@company.com), INTERNAL work documents, normal sync
Closure Reason: Approved corporate service, user domain matches, within baseline
Action: Close - recommend tuning to whitelist corporate OneDrive for @company.com users
```

**Example 2: Automated AWS S3 Backup**
```
Alert: Service account uploaded 1.2GB to AWS S3 at 1 AM
Risk Score: 5 (MEDIUM - volume + off-hours)
Investigation: AWS S3 /database-backups/ path, service account, scheduled task
Closure Reason: Approved automated backup, service account, expected behavior
Action: Close - whitelist svc-backup to AWS S3 /backups/ paths
```

**Example 3: Developer GitHub Release**
```
Alert: Engineering user uploaded 287MB to GitHub
Risk Score: 7 (HIGH - PROPRIETARY classification)
Investigation: Company GitHub org, /releases/ path, authorized release manager
Closure Reason: Approved developer workflow, company-owned repository, release artifacts
Action: Close - whitelist GitHub /releases/ and /artifacts/ for Engineering department
```

---

### Tier 5: CLOSE - BLOCKED BY CONTROLS

**When to Use:**
- **DLP blocked upload** - Data exfiltration prevented before completion
- **CASB prevented transfer** - Cloud access security broker blocked unauthorized service
- **Firewall blocked destination** - Destination IP/domain blocked at network perimeter
- **Upload failed** - Technical failure prevented data transfer

**Escalation Path:**
1. **Verify block was successful** - Confirm no data actually exfiltrated
2. **Document block details** (bytes transferred before block, data classification)
3. **Assess user intent** - Was this malicious attempt or accidental policy violation?
4. **Escalate if malicious intent** - Even if blocked, insider threat indicators require investigation
5. **Close if technical failure** - Network errors, service outages, etc.

**Examples:**

**Example 1: DLP Blocked PII Upload**
```
Alert: User attempted to upload 500MB containing 3,000 PII records to Dropbox
Risk Score: 18 (CRITICAL)
Investigation: DLP blocked at 2% completion (10MB transferred), user contacted IT about "upload error"
Disposition: CLOSE - BLOCKED, but escalate for user education (accidental policy violation)
Action: Close alert, send user to security awareness training on data handling policies
```

**Example 2: CASB Prevented Mega.nz Upload**
```
Alert: User attempted 200MB upload to Mega.nz
Risk Score: 15 (CRITICAL)
Investigation: CASB blocked connection to Mega.nz (on blocked service list), 0 bytes transferred
Disposition: CLOSE - BLOCKED, investigate user intent
Action: If accidental, close with warning. If deliberate circumvention attempt, escalate to HR
```

**Example 3: Network Failure - Not Malicious**
```
Alert: Large upload attempt detected, failed after 30 seconds
Risk Score: 8 (HIGH)
Investigation: Network outage caused upload failure, user reattempted successfully to approved OneDrive
Disposition: CLOSE - TECHNICAL FAILURE
Action: Close, no security concern (network issue, not malicious)
```

---

## Special Escalation Scenarios

### Scenario 1: Impossible Travel

**Definition:** User authenticated from two geographically distant locations in a timeframe that makes physical travel impossible.

**Indicators:**
- Authentication logs show login from Location A at Time 1
- Alert shows upload from Location B at Time 2
- Time difference < physically possible travel time

**Action:**
- **IMMEDIATE ESCALATION** - High confidence account compromise
- Disable account immediately
- Do NOT contact user (may alert attacker)
- Reset credentials, force MFA re-enrollment
- Forensic analysis of both login locations

**Example:**
```
User: CORP\mbrown
Last Login: New York (40.7128° N, 74.0060° W) at 17:30 EST
Alert: Moscow (55.7558° N, 37.6173° E) at 22:43 EST (5h13m later)
Distance: 4,667 miles / Flight time: ~10 hours
Disposition: IMPOSSIBLE - account compromised
Action: IMMEDIATE escalation, disable account
```

---

### Scenario 2: Off-Hours Bulk Uploads

**Definition:** Large volume uploads (>1GB cumulative) during off-hours (10 PM - 6 AM) from non-IT/non-admin accounts.

**Indicators:**
- Multiple uploads between 10 PM - 6 AM
- Non-IT department user
- Cumulative volume >1GB
- Not a service account

**Action:**
- **HIGH PRIORITY ESCALATION** if sensitive data classification
- Investigate user's typical work schedule (global employee? shift worker?)
- Check for recent HR events (resignation, PIP, termination pending?)
- Validate business justification with manager

**Example:**
```
User: CORP\asmith (Finance department)
Uploads: 
  - 11:47 PM: 340MB to Dropbox
  - 12:15 AM: 280MB to Dropbox  
  - 01:03 AM: 450MB to Dropbox
Cumulative: 1.07GB in 1h16m
DLP Classification: PII (customer records)
Disposition: Suspicious - off-hours bulk exfiltration pattern
Action: HIGH escalation - likely insider threat
```

---

### Scenario 3: Mass Upload Outbreak

**Definition:** Multiple users (5+ users) uploading to the same unauthorized destination within a short timeframe (1 hour).

**Indicators:**
- 5+ distinct users
- Same destination domain
- Within 1-hour window
- Unusual for organization

**Action:**
- **IMMEDIATE ESCALATION** - May indicate:
  - Mass account compromise (credential stuffing, malware)
  - Coordinated insider threat (rare but critical)
  - Shadow IT mass adoption (less critical but requires policy action)
- Do NOT investigate individually - escalate as outbreak

**Example:**
```
Destination: file.io (anonymous file sharing)
Users: 8 distinct users across Finance, HR, Engineering
Timeframe: 14:23 - 15:11 (48 minutes)
Volume: 3.2GB cumulative
Disposition: Outbreak - mass compromise or coordinated action
Action: IMMEDIATE escalation to IR for outbreak response
```

---

### Scenario 4: Tor/VPN/Proxy Usage During Upload

**Definition:** User uploading via Tor exit node, commercial VPN, or anonymizing proxy service.

**Indicators:**
- Source IP resolves to known Tor exit node
- Source IP matches commercial VPN provider (NordVPN, ExpressVPN, etc.)
- Source IP shows proxy/anonymizer characteristics

**Action:**
- **HIGH PRIORITY ESCALATION** - Legitimate users rarely need anonymization for cloud uploads
- Check corporate VPN usage (if corporate VPN, lower concern)
- Validate business justification (security researchers may legitimately use Tor)
- High suspicion if combined with sensitive data + unauthorized destination

**Example:**
```
User: CORP\jdoe
Source IP: 185.220.101.47 (Tor exit node)
Destination: mega.nz
Upload: 280MB, DLP: CONFIDENTIAL
Disposition: High suspicion - anonymization + anonymous service + sensitive data
Action: HIGH escalation - likely deliberate circumvention of monitoring
```

---

### Scenario 5: Lateral Movement to Exfiltration

**Definition:** User accessed sensitive file shares immediately before large upload.

**Indicators:**
- File access logs show access to sensitive shares (HR, Finance, Legal)
- Access by user outside normal job function
- Large upload within 10 minutes of file access

**Action:**
- **IMMEDIATE ESCALATION** - Classic exfiltration pattern
- Correlate file access with upload timing
- Validate user authorization for file share access
- Check for privilege escalation or credential theft

**Example:**
```
14:05 - User CORP\mbrown accessed \\fileserver\Finance\CustomerDB\ (not normal for Marketing user)
14:07 - Large file created: C:\Users\mbrown\AppData\Local\Temp\data.zip (890MB)
14:12 - Upload to Dropbox personal: 890MB
DLP: PII (customer database records)
Disposition: Unauthorized access + immediate exfiltration
Action: IMMEDIATE escalation - insider threat or compromised account
```

---

## Escalation Decision Flowchart

```
START: Alert Triggered (Risk Score 5+)
    |
    v
[1] Is data classification PII/PCI/PHI/CONFIDENTIAL?
    |
    YES --> [2] Is destination unauthorized/anonymous service?
    |           |
    |           YES --> IMMEDIATE ESCALATION (Tier 1)
    |           |
    |           NO --> [3] Is destination approved corporate service?
    |                   |
    |                   YES --> CLOSE - APPROVED (Tier 4)
    |                   |
    |                   NO --> HIGH ESCALATION (Tier 2)
    |
    NO --> [4] Is data classification INTERNAL/PROPRIETARY?
            |
            YES --> [5] Is destination approved?
            |           |
            |           YES --> CLOSE - APPROVED (Tier 4)
            |           |
            |           NO --> [6] Is user behavior within baseline (<2σ)?
            |                   |
            |                   YES --> MEDIUM INVESTIGATION (Tier 3)
            |                   |
            |                   NO --> HIGH ESCALATION (Tier 2)
            |
            NO --> [7] Is data classification PUBLIC?
                    |
                    YES --> [8] Is destination approved?
                    |           |
                    |           YES --> CLOSE - APPROVED (Tier 4)
                    |           |
                    |           NO --> [9] Is upload volume >500MB or baseline deviation >3σ?
                    |                   |
                    |                   YES --> MEDIUM INVESTIGATION (Tier 3)
                    |                   |
                    |                   NO --> CLOSE - LOW RISK (Tier 4)
                    |
                    NO --> [10] Data classification unknown/unclassified
                            |
                            --> MEDIUM INVESTIGATION (Tier 3)

SPECIAL CHECKS (run in parallel):
- Impossible travel detected? --> IMMEDIATE ESCALATION (Tier 1)
- Terminated/resigned employee? --> IMMEDIATE ESCALATION (Tier 1)
- Account compromise indicators? --> IMMEDIATE ESCALATION (Tier 1)
- Off-hours bulk upload (>1GB)? --> HIGH ESCALATION (Tier 2)
- Mass outbreak (5+ users)? --> IMMEDIATE ESCALATION (Tier 1)
- Tor/VPN + sensitive data? --> HIGH ESCALATION (Tier 2)
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│           DATA EXFILTRATION ESCALATION QUICK REFERENCE          │
├─────────────────────────────────────────────────────────────────┤
│ IMMEDIATE ESCALATION (15 min):                                  │
│  ✓ PII/PCI/PHI to unauthorized destination                      │
│  ✓ Terminated/resigned employee uploading                       │
│  ✓ Impossible travel detected                                   │
│  ✓ Anonymous service (Mega.nz, AnonFiles) + sensitive data      │
│  ✓ Account compromise confirmed                                 │
│  ✓ Lateral movement to exfiltration                             │
│  → ACTION: Notify IR immediately, disable account, document     │
├─────────────────────────────────────────────────────────────────┤
│ HIGH PRIORITY ESCALATION (1 hour):                              │
│  ✓ INTERNAL/PROPRIETARY to unapproved service                   │
│  ✓ High-risk dept (Finance/Legal/HR) to personal cloud          │
│  ✓ Off-hours upload without justification                       │
│  ✓ Large upload to unapproved service                           │
│  → ACTION: Investigate, contact manager, escalate to SOC lead   │
├─────────────────────────────────────────────────────────────────┤
│ MEDIUM INVESTIGATION (thorough analysis):                       │
│  ✓ First-time service usage                                     │
│  ✓ Shadow IT scenarios                                          │
│  ✓ BYOD personal cloud sync                                     │
│  ✓ Moderate baseline deviation (2-3σ)                           │
│  → ACTION: Investigate thoroughly, validate business case       │
├─────────────────────────────────────────────────────────────────┤
│ CLOSE - APPROVED:                                               │
│  ✓ Corporate OneDrive/SharePoint/Google Workspace               │
│  ✓ Service account backups to approved storage                  │
│  ✓ PUBLIC data classification                                   │
│  ✓ Within user baseline + approved service                      │
│  → ACTION: Document closure, recommend tuning if needed         │
├─────────────────────────────────────────────────────────────────┤
│ CLOSE - BLOCKED:                                                │
│  ✓ DLP blocked upload (0 bytes transferred)                     │
│  ✓ CASB prevented connection                                    │
│  ✓ Firewall blocked destination                                 │
│  → ACTION: Verify block, assess intent, close with notes        │
├─────────────────────────────────────────────────────────────────┤
│ KEY QUESTIONS:                                                  │
│  1. What data? (DLP classification)                             │
│  2. Where to? (Approved service? Anonymous?)                    │
│  3. Who? (Department, role, employment status)                  │
│  4. When? (Business hours? Off-hours? Weekend?)                 │
│  5. Normal? (Baseline deviation, historical behavior)           │
│  6. Why? (Business justification, manager approval)             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Common Escalation Mistakes

### Mistake 1: Escalating Every CRITICAL Alert Without Investigation

**Problem:** Not all CRITICAL risk scores are actual incidents.

**Correct Approach:** Investigate context first, then escalate if justified.

---

### Mistake 2: Closing Alerts on Approved Services Without Checking Data Classification

**Problem:** Corporate OneDrive can still be used maliciously.

**Correct Approach:** Even approved services require DLP validation.

---

### Mistake 3: Not Checking for Account Compromise

**Problem:** Assuming the user actually initiated the upload.

**Correct Approach:** Always check for impossible travel and failed login attempts.

---

### Mistake 4: Escalating Shadow IT Without Business Validation

**Problem:** Treating all unapproved services as malicious.

**Correct Approach:** Contact manager for business justification first.

---

### Mistake 5: Ignoring Service Account Context

**Problem:** Escalating off-hours uploads by service accounts.

**Correct Approach:** Check if user is service account, review historical patterns.

---

## Key Takeaways

1. **Context determines disposition** - Risk score prioritizes, investigation decides
2. **DLP is the most important factor** - Data classification drives escalation severity
3. **Service account uploads are usually legitimate** - Check historical patterns
4. **Impossible travel = immediate escalation** - High confidence account compromise
5. **Shadow IT isn't always malicious** - Validate business need before escalating to IR
6. **Insider threats are rare but critical** - Resigned/terminated employees require immediate action
7. **Document everything** - Your notes may be used in legal proceedings
8. **When in doubt, escalate** - Better to over-escalate than miss a real incident
