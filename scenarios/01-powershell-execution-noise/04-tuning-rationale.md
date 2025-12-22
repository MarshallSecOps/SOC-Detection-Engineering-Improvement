# Detection Tuning Rationale – PowerShell Execution Noise

## Objective
The objective of this tuning effort was to **reduce false positives** while maintaining visibility into genuinely suspicious PowerShell activity.

Rather than suppressing alerts entirely, the detection was redesigned to **correlate multiple contextual indicators** that better represent malicious tradecraft.

---

## Why Execution Policy Bypass Alone Is Insufficient
While `-ExecutionPolicy Bypass` is frequently observed in malicious PowerShell usage, it is also common in:

- Legitimate user scripts
- Administrative automation
- Backup and maintenance tasks

Treating this parameter as a standalone indicator results in excessive noise and reduced analyst trust in the alert.

---

## Indicators Selected for Correlation

### 1. Encoded or Obfuscated Execution
Indicators:
- `-EncodedCommand` or `-enc`
- Inline execution (`IEX`, `Invoke-Expression`)

**Rationale:**
Attackers commonly encode PowerShell payloads to evade detection and hinder analysis. These indicators strongly increase confidence in malicious intent when present.

---

### 2. Hidden or Stealthy Execution
Indicator:
- `-WindowStyle Hidden`

**Rationale:**
Legitimate scripts rarely need to hide execution from the user. Hidden windows suggest an attempt to conceal activity.

---

### 3. Suspicious Parent Processes
Indicators:
- Office applications (Word, Excel, Outlook)
- `cmd.exe`
- `wmiprvse.exe`

**Rationale:**
These parent processes are frequently associated with:
- Macro-based initial access
- Scripted execution
- Lateral movement

PowerShell launched from these contexts is significantly more suspicious than GUI-initiated execution.

---

### 4. Elevated Execution Context
Indicators:
- High or SYSTEM integrity level

**Rationale:**
Malicious PowerShell activity often seeks elevated privileges to enable persistence, credential access, or lateral movement. Elevated context increases potential impact and risk.

---

## Use of a Scoring Model
A simple scoring model was introduced to:

- Avoid binary alert logic
- Allow incremental confidence assessment
- Support future tuning without major rewrites

Alerts only trigger when **multiple suspicious indicators are present**, reducing false positives while preserving detection depth.

---

## Severity Assignment Logic
Severity is derived from the number of correlated indicators:

- **Low:** Multiple weak indicators present
- **Medium:** Clear suspicious execution patterns
- **High:** Strong indicators of malicious tradecraft

This supports consistent escalation decisions and aligns alert severity with analyst effort.

---

## Trade-offs and Risk Considerations
This tuning intentionally accepts the risk that:

- Some benign-but-unusual scripts may still alert
- Extremely minimal attacker tradecraft could evade detection

These trade-offs are acceptable in exchange for:
- Reduced alert fatigue
- Improved analyst confidence
- Higher-quality escalations

Detection engineering is an iterative process and should evolve as new data and threats emerge.

---

## Conclusion
This tuning effort demonstrates that **contextual correlation is more effective than single-indicator alerts**.

By focusing on execution context, obfuscation, privilege, and parent process relationships, the detection now surfaces PowerShell activity that is far more likely to represent genuine security risk.
