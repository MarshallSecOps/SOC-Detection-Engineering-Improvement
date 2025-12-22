# SOC Detection Engineering & Alert Quality Improvement

## Project Overview
This project focuses on **detection engineering and alert quality improvement** within a SOC environment.  
Rather than finding new attacks, the objective is to **reduce false positives, improve alert fidelity, and enhance escalation decision-making** so SOC analysts spend time on real threats instead of noise.

The project demonstrates how poorly designed alerts impact SOC efficiency — and how thoughtful tuning, contextual enrichment, and evidence-based logic can dramatically improve outcomes.

---

## Objective
To showcase **job-ready SOC maturity** by taking noisy, realistic alerts and transforming them into **high-confidence, operationally useful detections**.

This project is designed to answer a question SOC managers care deeply about:

> *“Can this analyst help reduce alert fatigue without missing real threats?”*

---

## Tools & Environment
- **SIEM:** Splunk Enterprise (Docker on macOS)
- **Index:** soc_alerts
- **Data:** Custom-generated SOC alert scenarios based on common enterprise environments
- **Frameworks:** MITRE ATT&CK, SOC Tier 1 / Tier 2 escalation models

---

## Skills Demonstrated
- Detection engineering and alert tuning
- False positive reduction strategies
- Contextual enrichment for SOC alerts
- Escalation threshold design
- SPL query refinement and optimisation
- SOC operational thinking (time, noise, risk)
- Professional security documentation

---

## Alert Scenarios Improved

### 1. PowerShell Execution Noise Reduction
**Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell  
**Common Problem:**  
Alerts triggering on `-ExecutionPolicy Bypass` alone create high false positive rates due to legitimate user scripts and automation.

**Why SOCs struggle with this alert:**
- Legitimate admin and user scripts frequently bypass execution policy
- Alerts fire without context (parent process, encoding, integrity level)
- Analysts waste time validating benign behaviour

**Detection Engineering Improvements:**
- Parent process validation (GUI vs macro vs service execution)
- Obfuscation and encoding detection
- Integrity level and execution context correlation
- Severity adjustment based on combined indicators

**Outcome:**
- Significant reduction in false positives
- Clear separation of benign automation vs malicious PowerShell usage
- Faster, more confident triage decisions

---

### 2. Authentication Failure Floods & Brute Force Signal Quality
**Technique:** T1110 – Brute Force  
**Common Problem:**  
Failed login alerts generate constant noise from VPN issues, password lockouts, and user error.

**Why SOCs struggle with this alert:**
- Alerts trigger on volume alone
- Internal user lockouts are treated the same as external attacks
- Privileged vs non-privileged accounts lack weighting

**Detection Engineering Improvements:**
- External vs internal source differentiation
- Privileged account weighting
- Time-based velocity thresholds
- Contextual escalation logic for successful logins after failures

**Outcome:**
- Reduced alert fatigue from benign lockouts
- Faster escalation of true attack scenarios
- Improved SOC confidence in brute force alerts

---

### 3. Data Exfiltration Alert Tuning for Cloud Environments
**Technique:** T1041 – Exfiltration Over Command and Control Channel  
**Common Problem:**  
Large outbound data transfers trigger alerts for normal cloud services (OneDrive, S3, backups).

**Why SOCs struggle with this alert:**
- Cloud traffic resembles exfiltration patterns
- Alerts lack destination reputation and method context
- Analysts spend time chasing legitimate business activity

**Detection Engineering Improvements:**
- Known cloud service baselining
- HTTP method analysis (POST vs PUT)
- Destination reputation and ASN context
- Volume thresholds aligned with business norms

**Outcome:**
- Fewer false positives from cloud sync and backup tools
- High-confidence detection of anomalous outbound transfers
- Clear escalation criteria for potential data loss events

---

## Methodology
Each alert follows a consistent detection engineering workflow:

1. **Baseline Review** – Understand why the alert exists and how it fires
2. **False Positive Analysis** – Identify common benign triggers
3. **Contextual Enrichment** – Add process, user, network, and timing context
4. **Logic Refinement** – Improve SPL logic and thresholds
5. **Operational Impact Assessment** – Evaluate SOC efficiency gains
6. **Documentation** – Clearly explain tuning decisions and trade-offs

---

## Key Takeaways
- Noisy alerts waste more SOC time than missed detections
- Context matters more than single indicators
- Good detection engineering balances **risk, signal quality, and analyst time**
- SOC effectiveness improves when alerts are designed with escalation in mind
- Alert tuning is a continuous, evidence-driven process

---

## Project Status
🚧 **In Progress** – Additional alert scenarios and tuning iterations planned

---

**Author:** Marshall  
**Role Target:** SOC Tier 1 / Tier 2 Analyst  
