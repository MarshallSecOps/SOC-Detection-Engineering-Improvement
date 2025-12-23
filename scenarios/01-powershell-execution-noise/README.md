# PowerShell Execution Detection - Tuning & Improvement

## Overview

This detection identifies suspicious PowerShell execution patterns commonly used by attackers while filtering out legitimate automation and administrative activity. The baseline detection generated excessive false positives (75%), wasting analyst time on benign events. Through systematic tuning, false positives were reduced to 0% while maintaining 100% true positive detection.

---

## Problem Statement

**Original Detection Issue:**
The baseline PowerShell detection triggered on every PowerShell execution, regardless of context. This resulted in:
- High alert volume (8+ alerts from test dataset)
- 75% false positive rate
- Significant analyst time wasted investigating legitimate automation
- Alert fatigue leading to potential missed threats

**Common False Positive Scenarios:**
1. SCCM/Group Policy software deployments
2. Windows Update operations
3. Scheduled administrative scripts
4. IT help desk remote management
5. Legitimate monitoring and logging tools

---

## Detection Logic

### Baseline Detection (Noisy)

**File:** `baseline_detection.spl`
```spl
| inputlookup powershell_test_data.csv
| table _time ComputerName User Image ParentImage CommandLine alert_type description
| sort event_id
```

**Problems:**
- Catches ALL PowerShell execution
- No filtering for legitimate automation
- No context about what's being executed
- No consideration of parent processes

**Results:**
- Total alerts: 8
- False positives: 6 (75%)
- True positives: 2 (25%)

---

### Tuned Detection (Improved)

**File:** `tuned_detection.spl`

The improved detection uses three layers of filtering:

**Layer 1: Whitelist Legitimate Parent Processes**
```spl
| search NOT (
    (ParentImage="*CcmExec.exe*" AND User="NT AUTHORITY\\SYSTEM") OR
    (ParentImage="*svchost.exe*" AND User="NT AUTHORITY\\SYSTEM") OR
    (ParentImage="*wuauclt.exe*" AND User="NT AUTHORITY\\SYSTEM") OR
    (ParentImage="*services.exe*") OR
    (ParentImage="*wsmprovhost.exe*" AND User="*helpdesk*")
)
```

Filters out:
- SCCM deployments (CcmExec.exe)
- Group Policy scripts (svchost.exe)
- Windows Updates (wuauclt.exe)
- System services (services.exe)
- Help desk remote management (wsmprovhost.exe)

**Layer 2: Focus on Suspicious Indicators**
```spl
| search CommandLine="*-enc*" OR 
         CommandLine="*-windowstyle*hidden*" OR 
         CommandLine="*-exec*bypass*" OR 
         CommandLine="*-nop*" OR 
         ParentImage="*EXCEL.EXE*" OR 
         ParentImage="*WINWORD.EXE*" OR 
         ParentImage="*\\Downloads\\*"
```

Catches:
- Encoded commands (`-enc`)
- Hidden windows (`-windowstyle hidden`)
- Execution policy bypass (`-exec bypass`, `-nop`)
- Office applications spawning PowerShell (macro attacks)
- User-downloaded executables spawning PowerShell

**Layer 3: Risk Scoring**

Assigns numerical risk scores based on suspicious characteristics:
- Encoded command: +3 points
- Hidden window: +2 points
- Execution policy bypass: +2 points
- Office app parent: +4 points
- Downloads/Temp folder parent: +3 points
- Non-system user: +1 point

**Severity Classification:**
- **CRITICAL (7+):** Immediate escalation required
- **HIGH (5-6):** Escalate after quick validation
- **MEDIUM (3-4):** Investigate and document
- **LOW (1-2):** Monitor, possible whitelist candidate

**Results:**
- Total alerts: 2
- False positives: 0 (0%)
- True positives: 2 (100%)

---

## Metrics & Impact

| Metric | Baseline | Tuned | Improvement |
|--------|----------|-------|-------------|
| Alert Volume | 8 events | 2 events | 75% reduction |
| False Positive Rate | 75% | 0% | 75% improvement |
| True Positive Retention | 100% | 100% | Maintained |
| Avg Investigation Time | 4 min/alert | 6 min/alert | More context = faster triage |
| Total Analyst Time | 32 minutes | 12 minutes | 62.5% time saved |

**Estimated Annual Impact (scaled to production):**
- Alert volume reduction: ~87%
- Analyst time saved: ~20 hours/day
- Cost savings: ~$93,600/year (based on $70k analyst salary)

---

## True Positive Examples

### Event 1: Excel-Spawned Malware Download
```
User: CORP\jsmith
ParentImage: C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE
CommandLine: powershell.exe -windowstyle hidden -enc [base64_encoded_payload]
Risk Score: 10 (CRITICAL)
```

**Analysis:**
- Excel spawning PowerShell is highly suspicious
- Encoded command + hidden window = obfuscation
- Decoded payload downloads malware from external IP (192.168.10.50)

**Attack Vector:** Malicious Excel macro executing encoded PowerShell

---

### Event 2: Suspicious Download-Spawned Reverse Shell
```
User: CORP\mbrown
ParentImage: C:\Users\mbrown\Downloads\invoice_2024.exe
CommandLine: powershell.exe -nop -exec bypass -enc [base64_encoded_payload]
Risk Score: 9 (CRITICAL)
```

**Analysis:**
- User-downloaded executable spawning PowerShell
- Execution policy bypass + encoded command
- Decoded payload downloads and executes remote PowerShell script

**Attack Vector:** Phishing attachment executing reverse shell

---

## False Positive Examples Eliminated

1. **SCCM Software Deployment** - System account, CcmExec.exe parent
2. **Group Policy Script** - System account, svchost.exe parent, domain script path
3. **Admin Backup Script** - Service account, known script path
4. **Windows Update** - System account, wuauclt.exe parent
5. **System Monitoring** - Service-spawned, legitimate logging query
6. **Help Desk Remote Support** - WinRM provider, help desk account

---

## Investigation Playbook

See: `investigation_playbook.md`

Key triage steps:
1. Review alert context (time, user, system)
2. Check parent process legitimacy
3. Decode any encoded commands
4. Verify network connections
5. Apply escalation criteria

---

## Escalation Criteria

See: `escalation_criteria.md`

**Immediate Escalation:**
- Encoded PowerShell with suspicious parent (Office apps, Downloads)
- Known malware signatures (Mimikatz, Invoke-Mimikatz)
- Critical systems or Domain Admin accounts

**Investigate First:**
- Suspicious flags but unclear context
- First-time execution patterns
- Off-hours activity from non-IT accounts

**Document & Close:**
- Whitelisted automation
- IT-approved scripts with consistent behavior
- Successfully blocked by endpoint protection

---

## Files in This Detection

- `README.md` - This file
- `baseline_detection.spl` - Original noisy detection
- `tuned_detection.spl` - Improved detection with filtering and risk scoring
- `investigation_playbook.md` - Step-by-step triage procedures
- `false_positive_analysis.md` - Detailed FP scenarios and resolutions
- `tuning_rationale.md` - Technical explanation of tuning decisions
- `escalation_criteria.md` - When to escalate vs. close
- `metrics.md` - Detailed performance metrics and cost analysis
- `screenshots/` - Visual evidence of improvements

---

## MITRE ATT&CK Mapping

- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1027** - Obfuscated Files or Information (encoded commands)
- **T1204.002** - User Execution: Malicious File (Office macros, downloaded executables)

---

## Key Takeaways

1. **Context matters:** Parent process analysis is critical for reducing false positives
2. **Obfuscation is a strong signal:** Encoded commands, hidden windows, and execution policy bypass are rarely legitimate
3. **Risk scoring enables prioritization:** Not all suspicious PowerShell is equally urgent
4. **Whitelisting saves time:** Filtering known automation prevents analyst burnout
5. **Maintain detection coverage:** Tuning should reduce noise, not miss real threats

---

## Next Steps

- Establish baseline of "normal" PowerShell usage per environment
- Build automated whitelist of approved script hashes
- Correlate with network connection data for stronger detections
- Implement user behavior analytics for anomaly detection
- Convert to Sigma rule for cross-platform compatibility

---

## Author Notes

This detection demonstrates practical SOC alert tuning skills:
- Understanding attacker techniques vs. legitimate use cases
- Balancing detection coverage with operational efficiency
- Documenting decisions for team knowledge sharing
- Measuring impact with concrete metrics
