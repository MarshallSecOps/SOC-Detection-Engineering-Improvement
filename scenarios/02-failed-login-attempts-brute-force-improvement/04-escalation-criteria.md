# Failed Login Attempts / Brute Force - Escalation Criteria

## Overview

This document defines clear escalation criteria for failed login attempt alerts. The goal is to provide analysts with objective decision-making guidelines to determine when authentication failures require escalation to Tier 2/Incident Response versus when they can be documented and closed.

**Key Principle:** Successful authentication after failures = Immediate escalation (confirmed compromise)

---

## Escalation Decision Tree

```
                        Failed Login Alert
                               |
                               v
                    [Check Risk Score]
                               |
              +----------------+----------------+
              |                |                |
         Risk >= 10       Risk 7-9         Risk 1-6
         (CRITICAL)        (HIGH)          (MED/LOW)
              |                |                |
              v                v                v
    [Check Success Count] [Check Source]  [Quick Validation]
              |                |                |
              v                v                v
      Success > 0?      External IP?      Benign Context?
              |                |                |
         +----+----+      +----+----+      +----+----+
         |         |      |         |      |         |
        Yes        No    Yes        No    Yes        No
         |         |      |         |      |         |
         v         v      v         v      v         v
    ESCALATE   Continue  Escalate Investigate Close Continue
    IMMEDIATE           After     Deeper           Investigation
                       Validation
```

---

## Immediate Escalation (CRITICAL)

**Escalate WITHOUT further investigation - time-critical incident response required**

### Condition 1: Confirmed Account Compromise
- **Trigger:** `success_count > 0` AND `failure_count > 10` in same 30-minute window
- **Explanation:** Attacker obtained valid credentials after brute force/spray attempt
- **Risk Score:** Typically 10-16
- **Action:** Page on-call IR team immediately

**Example:**
```
IpAddress: 203.0.113.45 (external)
Target: svc-backup
Failures: 87
Success: 1
Risk Score: 15
→ IMMEDIATE ESCALATION
```

**Immediate Actions Required:**
1. Disable compromised account(s)
2. Isolate affected systems
3. Review authentication logs for post-compromise activity
4. Check for lateral movement
5. Engage incident response team

---

### Condition 2: Brute Force Against Domain Admin
- **Trigger:** `privileged_target=1` AND `external_source=1` AND `failure_count > 50`
- **Explanation:** Organized attack targeting highest-privilege accounts
- **Risk Score:** Typically 9-13
- **Action:** Escalate immediately even without success

**Example:**
```
IpAddress: 198.51.100.67 (external)
Target: Administrator, domain-admin, backup-admin
Failures: 156
Success: 0
Risk Score: 13
→ IMMEDIATE ESCALATION
```

**Rationale:** Attack against Domain Admin accounts represents critical threat even if unsuccessful. Demonstrates advanced reconnaissance and high-value target selection.

---

### Condition 3: Known Malicious IP with Attack Pattern
- **Trigger:** IP flagged in threat intelligence AND (`spray_pattern=1` OR `failure_count > 25`)
- **Explanation:** Known attacker infrastructure actively targeting organization
- **Risk Score:** Typically 10-14
- **Action:** Escalate and block IP at perimeter

**Example:**
```
IpAddress: 192.0.2.88 (external)
Threat Intel: Known botnet C2, 47 abuse reports
Target: 12 unique accounts
Failures: 89
Risk Score: 12
→ IMMEDIATE ESCALATION
```

---

### Condition 4: Large-Scale Password Spray Campaign
- **Trigger:** `unique_users > 15` AND (`external_source=1` OR `rapid_velocity=1`)
- **Explanation:** Organized attack attempting systematic compromise
- **Risk Score:** Typically 10-12
- **Action:** Escalate, block source, enable enhanced monitoring

**Example:**
```
IpAddress: 203.0.113.22 (external)
Target: 23 unique accounts
Failures: 138
Pattern: Password spray
Risk Score: 11
→ IMMEDIATE ESCALATION
```

---

## Escalate After Investigation (HIGH)

**Investigate for 10-15 minutes, then escalate if suspicious indicators confirmed**

### Condition 5: External Source with Privileged Targeting (No Success Yet)
- **Trigger:** `external_source=1` AND `privileged_target=1` AND `success_count=0`
- **Investigation Required:** 
  - Verify IP is not approved remote access
  - Check if attack is ongoing or historical
  - Review target accounts for recent password changes
- **Risk Score:** Typically 7-9

**Investigation Steps:**
1. Check IP reputation (VirusTotal, AbuseIPDB)
2. Verify against approved remote access IPs
3. Review historical authentication from this IP
4. Check if attack is still active (last attempt < 15 min ago)
5. Review targeted accounts for security posture

**Escalate if:**
- IP has no legitimate business relationship
- Attack occurred within last hour (active threat)
- Multiple privileged accounts targeted
- Pattern suggests organized attack (not random)

**Close if:**
- IP is known VPN endpoint (verify with network team)
- Historical access pattern exists from this IP
- Attack stopped >24 hours ago with no success
- Single privileged account with business justification

---

### Condition 6: Internal Source with Spray Pattern
- **Trigger:** `external_source=0` AND `spray_pattern=1`
- **Investigation Required:**
  - Identify source system (workstation, server, infrastructure)
  - Check for malware/compromise indicators on source
  - Review user activity on source system
- **Risk Score:** Typically 5-9

**Investigation Steps:**
1. Look up source IP in asset inventory
2. Check EDR logs for suspicious processes on source system
3. Review recent user activity (who logged in?)
4. Check for macro execution, email attachments, downloads
5. Verify if source system has legitimate reason for authentication attempts

**Escalate if:**
- Source is user workstation with no business need for spray pattern
- EDR shows suspicious processes (pws.exe, mimikatz, etc.)
- Source was recently compromised (recent malware alerts)
- User denies initiating authentication attempts
- Pattern consistent with automated malware behavior

**Close if:**
- Source is known automation server with legitimate batch processing
- IT infrastructure performing system scans
- Network device performing health checks
- Service account with documented authentication requirements

---

### Condition 7: Off-Hours External Authentication Attempts
- **Trigger:** `external_source=1` AND `time between 00:00-06:00 local` AND `failure_count > 15`
- **Investigation Required:**
  - Verify if target users work off-hours shifts
  - Check if organization has 24/7 remote access requirements
  - Review geographical source of attempts
- **Risk Score:** Typically 6-9

**Investigation Steps:**
1. Check target user(s) work schedule
2. Verify if remote work is approved for these users
3. Review geolocation of source IP
4. Check if VPN or legitimate remote access gateway
5. Correlate with help desk tickets for access issues

**Escalate if:**
- Target users do not work night shifts
- Source IP geolocation inconsistent with user location
- No help desk tickets for legitimate access issues
- Pattern suggests automated attack tool
- Multiple users from same external IP (not VPN)

**Close if:**
- Users have approved night shift schedules
- Source is known VPN concentrator
- Help desk ticket confirms legitimate access attempts
- Geolocation matches user's approved remote work location

---

## Investigate & Document (MEDIUM)

**Thorough investigation required - escalate only if evidence of malicious intent found**

### Condition 8: Moderate Spray Pattern from Unclear Source
- **Trigger:** `unique_users > 5` AND `failure_count > 20` AND `risk_score 4-6`
- **Investigation Required:**
  - Determine source type and purpose
  - Validate target accounts and failure reasons
  - Check for legitimate business processes
- **Action:** Investigate thoroughly, document findings

**Investigation Steps:**
1. Identify source system owner/purpose
2. Check SubStatus codes for failure reasons
3. Review if accounts have recent password changes
4. Validate against known automation/service accounts
5. Check historical patterns from this source

**Escalate if:**
- No legitimate business justification found
- Inconsistent with normal environment behavior
- Source cannot be identified or validated
- Pattern evolves to higher severity

**Close if:**
- Source is approved automation (verify with IT)
- Service account password rotation in progress
- Known integration testing environment
- Clear documentation of business purpose

---

### Condition 9: Internal Failures with Account Enumeration
- **Trigger:** `external_source=0` AND `SubStatus=0xC0000064` (user doesn't exist) AND `unique_users > 10`
- **Investigation Required:**
  - Determine if legitimate directory query
  - Check for malware performing reconnaissance
  - Validate source system purpose
- **Action:** Investigate source system for compromise

**Investigation Steps:**
1. Identify source system and its role
2. Check for recent security alerts on source
3. Review running processes on source system
4. Validate if source has legitimate need for directory queries
5. Check if part of larger reconnaissance activity

**Escalate if:**
- Source is user workstation with no need for directory access
- Evidence of malware or suspicious processes
- Part of larger attack pattern (other reconnaissance)
- Cannot validate legitimate business purpose

**Close if:**
- Source is HR/IT system performing legitimate directory sync
- Known integration performing user validation
- Service account with documented directory access requirements

---

## Document & Close (LOW)

**Quick validation confirms benign activity - document and close**

### Condition 10: Single User Password Reset/Typo
- **Trigger:** `unique_users=1` AND `failure_count < 15` AND `external_source=0` AND `success_count > 0`
- **Investigation Required:** Minimal - verify success and context
- **Risk Score:** 1-3

**Quick Validation:**
1. Verify eventual successful login
2. Check if source IP matches user's regular workstation
3. Review help desk tickets for password reset
4. Confirm SubStatus is 0xC000006A (bad password)

**Close if:**
- User successfully authenticated from same source
- Help desk ticket confirms password reset
- Source is user's assigned workstation
- Timing consistent with password change transition

---

### Condition 11: Known VPN/Service Account Retry Loop
- **Trigger:** `TargetUserName LIKE "svc-%"` AND `WorkstationName LIKE "%VPN%"` AND `external_source=0`
- **Investigation Required:** Minimal - verify infrastructure pattern
- **Risk Score:** 0-2 (often whitelisted)

**Quick Validation:**
1. Verify source is known VPN infrastructure
2. Check if service account password recently changed
3. Review IT tickets for infrastructure issues
4. Confirm pattern matches known retry behavior

**Close if:**
- Source is documented VPN/infrastructure device
- Service account password mismatch documented
- IT ticket confirms ongoing resolution
- Pattern consistent with known retry loop behavior

---

### Condition 12: Mobile Device Cached Credentials
- **Trigger:** `unique_users=1` AND `failure_count < 20` AND `SubStatus=0xC000006A` AND eventual success
- **Investigation Required:** Minimal - verify user device scenario
- **Risk Score:** 1-3

**Quick Validation:**
1. Check if user recently changed password
2. Verify source is internal (mobile device connected to WiFi)
3. Confirm eventual successful authentication
4. Review timing between failures and success

**Close if:**
- User password changed within last 24 hours
- Internal source (corporate WiFi)
- Successful login after updating cached credentials
- User confirms mobile device scenario

---

## Special Scenarios

### Scenario A: Account Lockout Occurred
**Trigger:** `SubStatus=0xC0000234` (account locked)

**Immediate Actions:**
1. Determine lockout cause (attack vs. user error)
2. Review failures leading to lockout
3. Check if account is privileged
4. Validate user before unlocking

**Escalate if:**
- Privileged account locked due to external brute force
- User denies authentication attempts
- Lockout part of larger attack pattern
- Multiple accounts locked simultaneously

**Close if:**
- Single non-privileged user with documented password issues
- User confirms legitimate authentication attempts
- Help desk ticket for password reset exists

---

### Scenario B: Successful Login from New Geographic Location
**Trigger:** `success_count > 0` AND geolocation different from user's typical location

**Investigation Required:**
1. Check if user is traveling (HR records, calendar)
2. Verify if VPN or remote access approved
3. Review authentication method (MFA required?)
4. Check for impossible travel (login from 2 locations within short time)

**Escalate if:**
- Impossible travel scenario (2 continents in 1 hour)
- No travel authorization found
- MFA not used for unusual location
- User denies authentication attempt

**Close if:**
- User has approved travel to that location
- Business travel confirmed via HR/calendar
- MFA successfully completed
- Remote work approved from that location

---

### Scenario C: Credential Stuffing (Breached Password Lists)
**Trigger:** Mix of valid and invalid usernames, distributed botnet IPs

**Indicators:**
- High percentage of SubStatus 0xC0000064 (user doesn't exist)
- Multiple source IPs (botnet)
- Low failure rate per account (1-3 attempts)
- Known breached passwords in attempts

**Investigation Required:**
1. Identify which accounts exist in organization
2. Check for any successful authentications
3. Cross-reference with known breach databases
4. Verify password policies prevent common passwords

**Escalate if:**
- Any successful authentication occurred
- Valid accounts targeted with correct usernames
- Evidence of credential list from recent breach
- Multiple accounts show signs of compromise

---

## Risk Score Quick Reference

| Risk Score | Severity | Typical Action | Response Time |
|------------|----------|----------------|---------------|
| 10-16 | CRITICAL | Immediate Escalation | <15 minutes |
| 7-9 | HIGH | Escalate After Investigation | <1 hour |
| 4-6 | MEDIUM | Investigate & Document | <4 hours |
| 1-3 | LOW | Quick Validation & Close | <24 hours |

---

## Escalation Checklist

**Before Escalating, Verify:**
- [ ] Success correlation checked (Event ID 4624)
- [ ] Source IP identified and validated
- [ ] Target accounts identified and privilege level confirmed
- [ ] Attack pattern characterized (brute force vs spray vs stuffing)
- [ ] Related activity searched (lateral movement, data access)
- [ ] Documentation completed with evidence
- [ ] Clear articulation of why this is malicious

**Information to Include in Escalation:**
- Alert details (time, source IP, targets, failure/success counts)
- Risk score and severity
- Investigation findings (IP reputation, patterns, indicators)
- Compromised accounts (if success occurred)
- Related activity (lateral movement, data access)
- Recommended immediate actions
- Supporting evidence (logs, threat intel hits)

---

## Common Mistakes to Avoid

**Over-Escalation:**
- ❌ Escalating every internal failure without context
- ❌ Treating VPN retry loops as attacks
- ❌ Ignoring business context (password change windows)
- ❌ Not checking success correlation before escalating

**Under-Escalation:**
- ❌ Closing alerts with successful login after failures
- ❌ Dismissing external sources without investigation
- ❌ Ignoring spray patterns because "no success yet"
- ❌ Not correlating multiple low-severity alerts

**Investigation Shortcuts:**
- ❌ Not checking IP reputation
- ❌ Skipping success correlation step
- ❌ Not reviewing SubStatus codes
- ❌ Failing to search for related activity

---

## Continuous Improvement

**Monthly Review:**
- Review escalation decisions for accuracy
- Analyze false positive escalations
- Identify patterns requiring whitelist updates
- Update criteria based on new attack techniques

**Metrics to Track:**
- Escalation rate by risk score
- True positive rate for escalations
- Average investigation time by severity
- Time to escalation for CRITICAL alerts

**Feedback Loop:**
- Document escalation outcomes (true positive vs false positive)
- Share lessons learned with SOC team
- Update criteria based on missed detections
- Refine risk scoring based on actual attack patterns

---

## Quick Decision Guide

```
┌─────────────────────────────────────────────────────┐
│          Failed Login Alert Received                │
└──────────────────┬──────────────────────────────────┘
                   │
                   v
          ┌────────────────┐
          │ Success Count? │
          └────────┬───────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        v                     v
    Success > 0           Success = 0
        │                     │
        v                     v
  ESCALATE              ┌──────────┐
  IMMEDIATELY           │ External │
                        │  Source? │
                        └────┬─────┘
                             │
                   ┌─────────┴─────────┐
                   │                   │
                   v                   v
              External            Internal
                   │                   │
                   v                   v
          ┌─────────────┐      ┌──────────────┐
          │ Privileged  │      │ Spray        │
          │  Target?    │      │ Pattern?     │
          └──────┬──────┘      └──────┬───────┘
                 │                    │
        ┌────────┴────────┐  ┌────────┴────────┐
        │                 │  │                 │
        v                 v  v                 v
       Yes               No Yes               No
        │                 │  │                 │
        v                 v  v                 v
    ESCALATE         Investigate  Investigate   Quick
                     (HIGH)       (MEDIUM)     Validate
                                               (LOW)
```

---

**Remember:** When in doubt, escalate. Better to investigate a false positive than miss a real compromise.
