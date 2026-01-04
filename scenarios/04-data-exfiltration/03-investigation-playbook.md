# Data Exfiltration Detection - Investigation Playbook

## Overview

This playbook provides step-by-step procedures for investigating data exfiltration alerts. The average investigation takes **8-12 minutes** for straightforward cases, up to **30-45 minutes** for complex scenarios requiring deep analysis of user behavior, data classification validation, and account compromise assessment.

---

## Investigation Workflow

### Step 1: Review Alert Context (1-2 minutes)

**Objective:** Understand the alert severity, risk score components, and initial indicators

**Actions:**
1. Review alert fields:
   - **Risk score and severity** (CRITICAL/HIGH/MEDIUM)
   - **Upload volume** (how much data?)
   - **Data classification** (PII/PCI/PHI/CONFIDENTIAL/INTERNAL/PUBLIC?)
   - **Sensitive record count** (how many records?)
   - **Destination domain** (what service?)
   - **User and department** (who and what role?)
   - **Timestamp** (when? business hours vs. off-hours?)
   - **Baseline deviation** (normal behavior vs. anomaly?)

2. Make initial assessment:
   - Does the severity match the risk factors?
   - Are there obvious red flags (anonymous service + PII)?
   - Is this a known approved service for this user/department?

**SPL Query:**
```spl
index=proxy sourcetype=proxy user="CORP\\sjohnson" dest_domain="mega.nz"
| table _time user src_ip dest_domain upload_mb url dlp_classification sensitive_records department risk_score severity
| head 1
```

**Quick Wins:**
- CRITICAL severity + anonymous service (Mega.nz, AnonFiles) + sensitive data = **immediate escalation**
- HIGH severity + terminated employee user account = **immediate escalation**
- MEDIUM severity + approved service + public data = **likely false positive, validate and close**

---

### Step 2: Validate Destination Service (2-3 minutes)

**Objective:** Determine if the destination is an approved enterprise service or unauthorized cloud storage

**Actions:**
1. Identify the cloud service:
   - **Corporate approved?** (OneDrive/SharePoint, Google Workspace, Dropbox Business, Box)
   - **Personal account?** (personal Dropbox, personal Google Drive)
   - **Anonymous/attacker-favored?** (Mega.nz, AnonFiles, File.io, WeTransfer)
   - **Unknown/first-time service?** (requires validation with IT/procurement)

2. Check service tier:
   - Business tier? (URLs containing `/business/`, `/enterprise/`, `/company.com/`)
   - Personal tier? (generic paths, no corporate branding)

3. Validate user authorization:
   - Does user's department justify this service? (Marketing → YouTube, Developers → GitHub)
   - Is there a business case? (consult IT service catalog)

**SPL Query:**
```spl
index=proxy sourcetype=proxy user="CORP\\sjohnson" earliest=-30d
| stats count, values(dest_domain) as all_cloud_services by user
| where match(all_cloud_services, "mega.nz|dropbox|drive.google|box.com|onedrive")
```

**Decision Points:**
- **Approved corporate service + matching user domain** → Likely FP, verify data classification
- **Personal account of approved service** → Suspicious, continue investigation
- **Anonymous service** → High suspicion, escalate if sensitive data present
- **Unknown service** → Validate with IT, check threat intelligence

---

### Step 3: Analyze Data Classification (2-3 minutes)

**Objective:** Understand what data was uploaded and assess business impact

**Actions:**
1. Review DLP classification:
   - **CRITICAL:** PII, PCI, PHI, CONFIDENTIAL (customer data, financial data, health records, trade secrets)
   - **HIGH:** INTERNAL, PROPRIETARY (company internal documents, source code, business plans)
   - **MEDIUM:** Unclassified but business-related
   - **LOW:** PUBLIC (marketing materials, public documentation)

2. Check sensitive record count:
   - **>100 records** = bulk exfiltration concern
   - **10-100 records** = moderate concern
   - **<10 records** = low volume, may be legitimate sharing

3. Correlate DLP alerts:
   - Are there multiple DLP violations for this user/destination?
   - Was the upload blocked or allowed?
   - What specific data types triggered DLP?

**SPL Query:**
```spl
index=dlp sourcetype=dlp_alerts user="CORP\\sjohnson" dest_domain="mega.nz"
| table _time user dest_domain data_classification sensitive_record_count file_name file_size action
| sort -_time
```

**Decision Points:**
- **PII/PCI/PHI to unauthorized service** → Immediate escalation
- **CONFIDENTIAL to personal account** → Immediate escalation
- **INTERNAL to approved corporate service** → Likely legitimate, validate business justification
- **PUBLIC data** → Low concern unless extreme volume or suspicious destination

---

### Step 4: Examine User Behavior Baseline (2-3 minutes)

**Objective:** Determine if this upload is anomalous for this specific user

**Actions:**
1. Review historical upload patterns:
   - **Historical upload count:** Is user an established cloud user or first-time uploader?
   - **Average upload volume:** What's normal for this user?
   - **Standard deviation:** How consistent is their upload behavior?
   - **Baseline deviation:** How far is this upload from normal? (>3σ = 99.7% anomalous)

2. Identify service usage patterns:
   - Does user normally use this service?
   - First-time usage of this cloud platform?
   - Change in upload destinations recently?

3. Check temporal patterns:
   - Does user typically work off-hours?
   - Is this user a global employee (time zone considerations)?
   - Weekend activity normal for this role?

**SPL Query:**
```spl
index=proxy sourcetype=proxy user="CORP\\sjohnson" earliest=-90d bytes_out > 10485760
| eval upload_mb = round(bytes_out/1048576, 2)
| stats count as total_uploads, avg(upload_mb) as avg_mb, stdev(upload_mb) as stdev_mb, values(dest_domain) as all_destinations by user
| eval current_upload_mb = 487
| eval deviation = round((current_upload_mb - avg_mb) / stdev_mb, 2)
```

**Decision Points:**
- **>3σ deviation + first-time service** → High suspicion, escalate
- **<2σ deviation + established service** → Likely normal behavior
- **First-time uploader (<5 historical uploads)** → Requires validation, may be new employee or behavior change
- **Consistent with baseline** → Low concern unless sensitive data present

---

### Step 5: Assess User and Account Context (1-2 minutes)

**Objective:** Understand user risk profile and check for account compromise indicators

**Actions:**
1. Review user profile:
   - **Department and role:** Does role justify cloud storage usage?
   - **High-risk department?** (Finance, Legal, HR, Engineering)
   - **Recent employment changes:** New hire, pending resignation, terminated?
   - **Disciplinary action or PIP in progress?**

2. Check account compromise indicators:
   - **Recent failed login attempts** (brute force preceding upload?)
   - **Impossible travel** (login from US, upload from Russia 10 mins later?)
   - **MFA bypass or anomalies**
   - **Password reset requests**

3. Correlate with HR data:
   - **Employee status:** Active, terminated, resigned, PIP?
   - **Access level changes:** Recent privilege escalation or de-escalation?
   - **Manager:** Who to contact for business justification?

**SPL Query - Account Compromise Check:**
```spl
index=windows sourcetype=WinEventLog:Security user="sjohnson" (EventCode=4625 OR EventCode=4624 OR EventCode=4648)
| eval event_type = case(
    EventCode=4625, "Failed Login",
    EventCode=4624, "Successful Login",
    EventCode=4648, "Explicit Credential Use"
)
| table _time user src_ip event_type
| sort -_time
| head 50
```

**SPL Query - Impossible Travel:**
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4624 user="sjohnson" earliest=-24h
| iplocation src_ip
| stats values(City) as cities, values(Country) as countries, earliest(_time) as first_login, latest(_time) as last_login by user
| eval time_diff_minutes = round((last_login - first_login) / 60, 0)
```

**Decision Points:**
- **Terminated employee** → Immediate escalation (data theft before exit)
- **Account compromise indicators** → Escalate to IR team
- **High-risk department + unauthorized service** → Escalate for policy review
- **Normal employee + approved service** → Likely legitimate

---

### Step 6: Check Endpoint Activity (2-3 minutes)

**Objective:** Identify file staging, USB usage, or malicious process execution on the source endpoint

**Actions:**
1. Review file creation/modification events:
   - Were files staged to a temporary directory before upload?
   - Unusual file access patterns (e.g., accessing HR shared drive by non-HR user)?
   - Large archive files created (e.g., .zip, .rar of customer database)?

2. Check USB/removable media activity:
   - Was data copied to USB before cloud upload?
   - External drive connected during upload timeframe?

3. Look for exfiltration tools:
   - WinRAR/7-Zip compressing large datasets?
   - FTP clients or file transfer utilities?
   - Suspicious PowerShell or scripts running?

**SPL Query - File Staging:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=11 ComputerName="WORKSTATION-123" earliest=-1h latest=now
| eval file_path_lower = lower(TargetFilename)
| where like(file_path_lower, "%\\temp\\%") OR like(file_path_lower, "%\\downloads\\%") OR like(file_path_lower, "%\\appdata\\local\\temp\\%")
| stats count, values(TargetFilename) as files_created, sum(FileSize) as total_bytes by User
| eval total_mb = round(total_bytes/1048576, 2)
| where total_mb > 50
```

**SPL Query - USB Activity:**
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=2 ComputerName="WORKSTATION-123" earliest=-1h
| where like(TargetFilename, "E:\\%") OR like(TargetFilename, "F:\\%") OR like(TargetFilename, "G:\\%")
| table _time User TargetFilename Image
```

**Decision Points:**
- **Large archive created + cloud upload** → Likely deliberate exfiltration
- **USB staging + cloud upload** → High suspicion, data copied to multiple destinations
- **Unusual file access + upload** → Investigate file access justification
- **No staging activity** → May be direct upload from normal work location

---

### Step 7: Review Historical Activity (1-2 minutes)

**Objective:** Identify patterns of escalating suspicious behavior or one-time anomaly

**Actions:**
1. Search for similar alerts:
   - Has this user triggered exfiltration alerts before?
   - Is this part of a trend (increasing upload volumes over time)?
   - Previous alerts closed as FP or TP?

2. Check for related security events:
   - Recent malware detections on user's endpoint?
   - Phishing email clicks in user's mailbox?
   - Other policy violations (acceptable use, data handling)?

3. Identify potential insider threat indicators:
   - Multiple policy violations over time?
   - Access to sensitive systems/data beyond job requirements?
   - Behavioral changes noted by manager or colleagues?

**SPL Query - Historical Alerts:**
```spl
index=proxy sourcetype=proxy user="CORP\\sjohnson" earliest=-90d bytes_out > 10485760
| where NOT (like(dest_domain, "%sharepoint%") OR like(dest_domain, "%onedrive%"))
| stats count as alert_count, values(dest_domain) as all_destinations, sum(bytes_out) as total_bytes_uploaded by user
| eval total_mb_uploaded = round(total_bytes_uploaded/1048576, 2)
```

**SPL Query - Malware Correlation:**
```spl
index=edr sourcetype=edr_alerts user="sjohnson" earliest=-30d
| stats count by alert_type, severity
```

**Decision Points:**
- **Repeat offender (multiple alerts)** → Escalate for insider threat assessment
- **One-time anomaly + legitimate explanation** → Close with documentation
- **Recent malware detection + exfiltration** → Escalate to IR (compromised account)
- **Clean history** → Lower concern, likely FP or legitimate one-time event

---

### Step 8: Make Disposition Decision (1 minute)

**Objective:** Determine final action based on investigation findings

**Disposition Options:**

1. **ESCALATE IMMEDIATELY (CRITICAL/HIGH)**
   - PII/PCI/PHI/CONFIDENTIAL to unauthorized service
   - Insider threat indicators (terminated employee, PIP, multiple violations)
   - Account compromise confirmed
   - Anonymous file sharing with sensitive data
   - Extreme volume + extreme baseline deviation

2. **ESCALATE AFTER MANAGER VALIDATION (HIGH/MEDIUM)**
   - INTERNAL/PROPRIETARY to unapproved service
   - First-time cloud service usage without business justification
   - High-risk department to personal cloud account
   - Business justification required but not documented

3. **INVESTIGATE FURTHER / REQUEST INFORMATION (MEDIUM)**
   - Shadow IT scenario (unapproved but potentially legitimate SaaS)
   - Borderline risk score requiring additional context
   - User explanation needed for business justification

4. **CLOSE - APPROVED ACTIVITY (MEDIUM/LOW)**
   - Approved corporate service with proper authorization
   - Public data classification
   - Business justification confirmed by manager
   - Within user's normal behavior baseline

5. **CLOSE - BLOCKED BY CONTROLS (ANY SEVERITY)**
   - DLP blocked upload before completion
   - CASB prevented data transfer
   - No data actually left the network

**Documentation Required for All Dispositions:**
- Investigation summary (2-3 sentences)
- Key findings (data classification, destination, user context)
- Disposition rationale (why escalated or closed)
- Follow-up actions (if any)

---

## Investigation Examples

### Example 1: CRITICAL - Finance Insider Threat Exfiltration

**Alert Details:**
```
Time: 2024-12-15 02:37:18 (Sunday, 2:37 AM)
User: CORP\sjohnson
Department: Finance
Dest_domain: mega.nz
Upload_MB: 487
DLP_classification: PII, PCI
Sensitive_records: 2,847
Baseline_deviation: 4.8σ
Historical_uploads: 3
Risk_score: 19 (CRITICAL)
```

**Investigation Steps:**

**Step 1 - Alert Context:** CRITICAL severity, anonymous file sharing service, 487MB upload containing 2,847 PII/PCI records. Immediate red flag.

**Step 2 - Destination Validation:** Mega.nz = anonymous file sharing, attacker-favored service, zero business justification possible.

**Step 3 - Data Classification:** 2,847 customer credit card records detected by DLP. Extreme business impact if exfiltrated.

**Step 4 - User Baseline:** 4.8σ deviation, only 3 historical uploads (all to corporate OneDrive). First time ever using Mega.nz.

**Step 5 - User Context:** Finance department, access to customer billing database. **HR check reveals employee resigned Friday (2 days ago), effective date next Friday.**

**Step 6 - Endpoint Activity:** 
```spl
Large archive created: C:\Users\sjohnson\AppData\Local\Temp\customer_data.7z (487MB)
File created: 2024-12-15 02:15:00
Upload started: 2024-12-15 02:37:18
Source files: \\fileserver\Finance\CustomerBilling\*.csv (accessed 02:10-02:14)
```

**Step 7 - Historical Activity:** No previous security alerts. Clean record until resignation announcement.

**Step 8 - Disposition:** **IMMEDIATE ESCALATION TO IR + LEGAL**

**Action Taken:**
- Disabled user account immediately (02:45 AM)
- DLP blocked upload at 15% completion (71MB transferred, 2,847 records in queue but not uploaded)
- Forensic image of workstation captured
- Legal contacted for potential criminal charges
- Manager notified, user escorted from building Monday morning
- Law enforcement referral initiated

**Outcome:** Employee arrested for attempted theft of trade secrets. DLP prevented full exfiltration. 71MB transferred to Mega.nz, legal subpoena served to Mega.nz for account deletion (no evidence of download by external party). Employee prosecuted.

**Lessons Learned:** Off-hours + weekend + resigned employee + anonymous service + sensitive data = textbook insider threat. DLP saved the company from catastrophic breach.

---

### Example 2: HIGH - Compromised Account Data Exfiltration

**Alert Details:**
```
Time: 2024-11-08 03:14:52 (Thursday, 3:14 AM)
User: CORP\mbrown
Department: Marketing
Dest_domain: dropbox.com/personal
Upload_MB: 215
DLP_classification: INTERNAL, PROPRIETARY
Sensitive_records: 47
Baseline_deviation: 3.2σ
Historical_uploads: 127
Risk_score: 13 (CRITICAL)
```

**Investigation Steps:**

**Step 1 - Alert Context:** CRITICAL severity, 215MB upload to personal Dropbox (not business tier), 47 proprietary documents. User has high historical uploads (127) but to different services.

**Step 2 - Destination Validation:** Personal Dropbox account (URL: `dropbox.com/u/123456789/personal`), not corporate Dropbox Business. Suspicious for established user.

**Step 3 - Data Classification:** 47 INTERNAL/PROPRIETARY documents including unreleased product roadmaps, marketing strategies, competitive analysis.

**Step 4 - User Baseline:** User historically uploads ONLY to corporate OneDrive/SharePoint (127 uploads over 90 days). 3.2σ deviation. **First time EVER using personal Dropbox from corporate network.**

**Step 5 - User Context:** 
```spl
index=windows EventCode=4625 user="mbrown" earliest=-7d
| stats count by src_ip
| where count > 50
```
**Result:** 237 failed login attempts from IP 45.142.212.47 (Russian IP) over past 48 hours. **Successful login from same IP at 2024-11-07 22:43:15** (5 hours before upload).

**Impossible Travel Detected:**
- Last legitimate login: New York, 2024-11-07 17:30:00
- Suspicious login: Moscow, 2024-11-07 22:43:15 (5 hours 13 minutes later = impossible)

**Step 6 - Endpoint Activity:** No local file staging detected. Upload originated from VPN connection with Russian IP.

**Step 7 - Historical Activity:** **Phishing email clicked 2024-11-05** (3 days before compromise). User reported "suspicious email" after clicking link.

**Step 8 - Disposition:** **IMMEDIATE ESCALATION TO IR - ACCOUNT COMPROMISE**

**Action Taken:**
- Disabled account immediately (03:18 AM)
- CASB blocked upload at 47 files (215MB total, 15MB actually uploaded before block)
- Forced password reset for user
- Contacted user at home (confirmed they were asleep, not working at 3 AM)
- Forensic review of user's workstation
- Reset credentials for all users with similar phishing email exposure
- Enhanced monitoring on user's account for 30 days post-restoration

**Outcome:** Phishing email delivered credential-stealing malware. Attacker logged in from Russia, attempted to exfiltrate proprietary marketing documents. CASB prevented full exfiltration. User's account restored after credential reset, malware removed, and security awareness training completed.

**Lessons Learned:** Impossible travel + off-hours + first-time personal cloud usage + recent phishing = classic account compromise. CASB integration critical for blocking in-flight exfiltration.

---

### Example 3: MEDIUM - Shadow IT Legitimate Business Usage

**Alert Details:**
```
Time: 2024-10-18 14:22:37 (Friday, 2:22 PM)
User: CORP\alee
Department: Sales
Dest_domain: wetransfer.com
Upload_MB: 340
DLP_classification: PUBLIC
Sensitive_records: 0
Baseline_deviation: 2.1σ
Historical_uploads: 67
Risk_score: 6 (MEDIUM)
```

**Investigation Steps:**

**Step 1 - Alert Context:** MEDIUM severity, 340MB upload to WeTransfer (file sharing service), PUBLIC data classification, no sensitive records. Business hours activity.

**Step 2 - Destination Validation:** WeTransfer not on approved service list, but commonly used for large file transfers. Not anonymous service (requires sender email).

**Step 3 - Data Classification:** DLP scanned files: product demo videos (public marketing materials), no sensitive data detected.

**Step 4 - User Baseline:** 67 historical uploads, average 120MB, stdev 55MB. Current upload (340MB) is 2.1σ above average - elevated but not extreme.

**Step 5 - User Context:** Sales department, **manager confirms user is sending product demo videos to prospective client (Fortune 500 company)**.

**Step 6 - Endpoint Activity:** Files originated from `\\fileserver\Marketing\PublicDemos\` (approved public content repository).

**Step 7 - Historical Activity:** User has used WeTransfer 12 times in past 90 days for similar customer demos. **Consistent pattern of legitimate business usage.**

**Step 8 - Disposition:** **CLOSE - APPROVED SHADOW IT (with follow-up action)**

**Action Taken:**
- Validated with manager: legitimate customer demo delivery
- **Follow-up:** Submitted request to IT to add WeTransfer to approved service list for Sales department
- **Policy update:** Sales team authorized to use WeTransfer for PUBLIC content only (not INTERNAL/CONFIDENTIAL)
- Alert tuning: Whitelist WeTransfer for Sales department + PUBLIC classification

**Outcome:** Legitimate business usage of unapproved service (shadow IT). No security incident. Policy updated to formally approve WeTransfer for Sales, preventing future alerts while maintaining security controls (DLP still monitors for sensitive data).

**Lessons Learned:** Not all unapproved services are malicious. Shadow IT often fills legitimate business needs. Investigate context, validate with manager, and update policy accordingly rather than blanket blocking.

---

### Example 4: LOW - Approved Corporate Backup

**Alert Details:**
```
Time: 2024-12-10 01:15:47 (Tuesday, 1:15 AM)
User: CORP\svc-backup
Department: IT
Dest_domain: s3.amazonaws.com
Upload_MB: 1,240
DLP_classification: INTERNAL
Sensitive_records: 0
Baseline_deviation: 0.3σ
Historical_uploads: 1,247
Risk_score: 5 (MEDIUM)
```

**Investigation Steps:**

**Step 1 - Alert Context:** MEDIUM severity (risk_score = 5, barely above threshold), very large upload (1.2GB), service account, off-hours. INTERNAL classification.

**Step 2 - Destination Validation:** AWS S3, URL: `s3.amazonaws.com/company-backups/database-backups/prod-db-2024-12-10.bak`. Corporate-owned S3 bucket, `/database-backups/` path.

**Step 3 - Data Classification:** DLP flags INTERNAL due to database backup content. Expected for backup operations.

**Step 4 - User Baseline:** Service account with 1,247 historical uploads (nightly backups). 0.3σ deviation = perfectly normal behavior.

**Step 5 - User Context:** `svc-backup` = service account for automated database backups. IT department. **Scheduled task runs nightly at 01:00 AM.**

**Step 6 - Endpoint Activity:** Backup script: `C:\Scripts\Backup-Database.ps1` executed by Task Scheduler at 01:00 AM.

**Step 7 - Historical Activity:** Identical backups every night for past 3 years. Zero security incidents associated with this account.

**Step 8 - Disposition:** **CLOSE - APPROVED AUTOMATED BACKUP (tuning required)**

**Action Taken:**
- Confirmed legitimate nightly database backup
- **Tuning update:** Alert updated to whitelist AWS S3 with `/backups/` or `/database-backups/` path
- **Whitelist:** Service accounts (svc-*) uploading to approved backup destinations should not trigger alerts

**Outcome:** False positive. Legitimate automated backup operation. Detection tuned to prevent future alerts on approved backup services.

**Lessons Learned:** Service accounts performing automated backups should be whitelisted. Even INTERNAL data classification is expected for backups. Baseline analysis (0.3σ) clearly indicated normal behavior.

---

### Example 5: MEDIUM - Developer GitHub Release (Approved Usage)

**Alert Details:**
```
Time: 2024-11-22 16:45:12 (Friday, 4:45 PM)
User: CORP\jdoe
Department: Engineering
Dest_domain: github.com
Upload_MB: 287
DLP_classification: PROPRIETARY (source code)
Sensitive_records: 1
Baseline_deviation: 1.8σ
Historical_uploads: 234
Risk_score: 7 (HIGH)
```

**Investigation Steps:**

**Step 1 - Alert Context:** HIGH severity, 287MB upload to GitHub, PROPRIETARY classification (source code), business hours. Engineering department.

**Step 2 - Destination Validation:** GitHub.com, URL: `github.com/company-org/project-repo/releases/v2.4.1/build-artifacts.zip`. **Company GitHub organization, `/releases/` path = artifact publishing, not source code exfil.**

**Step 3 - Data Classification:** DLP flags PROPRIETARY because compiled binaries derived from proprietary source. Expected for software releases.

**Step 4 - User Baseline:** 234 historical uploads (active developer), average 95MB. 287MB is 1.8σ above average - slightly elevated but within normal range for release artifacts.

**Step 5 - User Context:** Senior software engineer, **release manager for project-repo**. GitHub releases are part of normal job function.

**Step 6 - Endpoint Activity:** Build artifacts created by CI/CD pipeline, developer uploading final release package.

**Step 7 - Historical Activity:** User uploads to GitHub `/releases/` path 15-20 times per quarter (aligned with release schedule). Consistent pattern.

**Step 8 - Disposition:** **CLOSE - APPROVED DEVELOPER ACTIVITY (tuning required)**

**Action Taken:**
- Validated with engineering manager: legitimate software release (v2.4.1)
- **Tuning update:** Whitelist GitHub `/releases/` and `/artifacts/` paths for Engineering department users
- **Policy:** Developers authorized to publish to company GitHub organization

**Outcome:** False positive. Legitimate software release by authorized developer. Detection tuned to whitelist developer release workflows while maintaining security on source code repositories.

**Lessons Learned:** Developer workflows involve large uploads to code repositories. `/releases/` and `/artifacts/` paths indicate publishing, not exfiltration. Context-aware whitelisting (path + department + organization ownership) prevents FPs without sacrificing security.

---

## Common Pitfalls to Avoid

### 1. Assuming All Personal Cloud Storage Is Malicious

**Pitfall:** Automatically escalating any personal Dropbox/Google Drive usage without investigating context.

**Reality:** Employees may legitimately use personal accounts for work-from-home scenarios, BYOD devices, or approved flexible work arrangements.

**Correct Approach:** Validate with manager, check HR policy on BYOD, assess data classification. Personal cloud + PUBLIC data + manager approval = legitimate. Personal cloud + PII = escalate.

---

### 2. Ignoring Service Account Context

**Pitfall:** Escalating off-hours uploads without checking if the user is a service account.

**Reality:** Service accounts (`svc-backup`, `svc-admin`) perform automated tasks 24/7. Off-hours activity is expected and normal.

**Correct Approach:** Check if user matches service account naming convention (`svc-*`, `admin-*`). Review historical upload patterns for consistency.

---

### 3. Over-Relying on Risk Score Alone

**Pitfall:** Escalating every HIGH risk score alert without investigation.

**Reality:** Risk scores are weighted indicators, not definitive verdicts. A HIGH score may be legitimate activity with unusual characteristics.

**Correct Approach:** Use risk score as prioritization guide, not disposition decision. Investigate context, validate business justification, document findings.

---

### 4. Failing to Correlate with DLP

**Pitfall:** Treating all 500MB uploads the same regardless of content.

**Reality:** 500MB of marketing videos (PUBLIC) is fundamentally different from 500MB of customer PII.

**Correct Approach:** ALWAYS check DLP classification. Data classification is the most important factor in exfiltration assessment.

---

### 5. Not Checking for Account Compromise

**Pitfall:** Assuming the user actually initiated the upload.

**Reality:** Compromised credentials allow attackers to use legitimate user accounts. Impossible travel, failed login attempts, and phishing correlation are critical.

**Correct Approach:** Always check authentication logs, geographic anomalies, and recent security events before attributing activity to the user.

---

### 6. Closing Alerts Too Quickly on "Approved" Services

**Pitfall:** Auto-closing alerts on OneDrive/SharePoint without checking data classification or user authorization.

**Reality:** Corporate OneDrive can still be used maliciously (e.g., uploading PII to personal OneDrive from corporate account).

**Correct Approach:** Validate user domain matches service domain, check for `/personal/` vs. `/business/` paths, assess data classification.

---

### 7. Ignoring Baseline Deviation

**Pitfall:** Focusing only on absolute upload volume, ignoring user's historical behavior.

**Reality:** 100MB upload may be normal for one user, extreme for another. Baseline deviation (sigma) provides user-specific context.

**Correct Approach:** Prioritize alerts with >3σ deviation regardless of absolute volume. A user uploading 50MB when their average is 5MB (high sigma) is more suspicious than uploading 500MB when their average is 450MB (low sigma).

---

### 8. Not Documenting Business Justification

**Pitfall:** Closing alerts verbally without written documentation or manager confirmation.

**Reality:** Insider threat cases require audit trails. "User said it was legitimate" is insufficient for legal proceedings.

**Correct Approach:** Document manager approval, business justification, and disposition rationale in SIEM. Email confirmation for high-risk closures.

---

## Investigation Documentation Template

**For Every Alert, Document:**

```
ALERT ID: [Alert ID from SIEM]
INVESTIGATION DATE: [Date/Time]
ANALYST: [Your name]

ALERT SUMMARY:
User: [Username]
Department: [Department]
Destination: [Domain/Service]
Upload Volume: [MB]
Data Classification: [DLP classification]
Sensitive Records: [Count]
Risk Score: [Score] / Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Timestamp: [Date/Time of upload]

KEY FINDINGS:
- [Finding 1: e.g., "Anonymous file sharing service (Mega.nz)"]
- [Finding 2: e.g., "2,847 PII records detected by DLP"]
- [Finding 3: e.g., "4.8σ baseline deviation - first time using this service"]
- [Finding 4: e.g., "Employee resigned 2 days ago, effective date next week"]

INVESTIGATION ACTIONS:
- [Action 1: e.g., "Validated destination service: Mega.nz = anonymous file sharing"]
- [Action 2: e.g., "Reviewed DLP details: Customer credit card data"]
- [Action 3: e.g., "Checked HR status: Employee resigned Friday"]
- [Action 4: e.g., "Endpoint analysis: Large archive created in Temp folder"]

DISPOSITION: [ESCALATE / CLOSE - APPROVED / CLOSE - BLOCKED / INVESTIGATE FURTHER]

DISPOSITION RATIONALE:
[2-3 sentence explanation of why you made this disposition decision]

ACTIONS TAKEN:
- [Action 1: e.g., "Disabled user account immediately"]
- [Action 2: e.g., "Contacted IR team and Legal"]
- [Action 3: e.g., "DLP blocked upload at 15% completion"]

FOLLOW-UP REQUIRED:
- [Follow-up 1: e.g., "Manager interview Monday morning"]
- [Follow-up 2: e.g., "Forensic analysis of workstation"]
- [Follow-up 3: e.g., "Legal subpoena to Mega.nz for account deletion"]

LESSONS LEARNED / TUNING RECOMMENDATIONS:
[Any detection tuning or process improvements identified]
```

---

## Escalation Contact Information

**Immediate Escalation (CRITICAL):**
- **Security Incident Response Team:** ir-team@company.com / Slack: #incident-response
- **Manager:** [Your SOC Manager]
- **Legal (for insider threat/criminal activity):** legal@company.com

**High Priority Escalation (HIGH):**
- **Security Operations Lead:** soc-lead@company.com
- **IT Security Team:** it-security@company.com

**Medium Priority (MEDIUM - requires validation):**
- **User's Manager:** [Look up in AD]
- **IT Service Desk:** servicedesk@company.com

---

## Key Takeaways

1. **Context is everything** - Risk score guides prioritization, but investigation reveals the truth
2. **DLP integration is critical** - Data classification determines business impact
3. **Baseline analysis prevents false positives** - User behavior context is essential
4. **Account compromise is common** - Always check authentication logs and impossible travel
5. **Document thoroughly** - Insider threat cases may end up in court
6. **Shadow IT isn't always malicious** - Investigate business justification before escalating
7. **Service accounts are automated** - Don't escalate scheduled backups
8. **Manager validation is required** - Business justification must be documented

**Average Investigation Time:**
- **Simple FP (approved service):** 3-5 minutes
- **Standard investigation:** 8-12 minutes
- **Complex investigation (compromise/insider threat):** 30-45 minutes

**Pro Tip:** Use the risk score to prioritize your queue, but NEVER skip the investigation steps. A CRITICAL alert may be a FP (approved backup with large volume), and a MEDIUM alert may be a TP (insider threat with clever techniques).
