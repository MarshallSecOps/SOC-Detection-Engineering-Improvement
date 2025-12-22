# Scenario 01 – PowerShell Execution Noise Reduction

## Scenario Overview
This scenario focuses on **reducing false positives in PowerShell execution alerts**, one of the most common and noisy detections in SOC environments.

PowerShell is a powerful administrative and automation tool that is also frequently abused by attackers. Poorly designed detections often trigger on benign activity, overwhelming SOC analysts and obscuring genuinely malicious behavior.

This scenario demonstrates how to **identify why an alert is noisy**, analyse false positive patterns, and apply **detection engineering techniques** to improve alert fidelity without reducing visibility.

---

## Why This Scenario Matters in a SOC
PowerShell alerts are a frequent source of alert fatigue because:

- Legitimate user scripts often bypass execution policy
- Administrative automation closely resembles attacker tradecraft
- Alerts frequently lack execution context
- Analysts are forced to manually validate benign behavior

A SOC that cannot distinguish **benign PowerShell automation** from **malicious PowerShell abuse** risks both:
- Missing real attacks
- Burning analyst time on non-incidents

This scenario reflects a **real SOC pain point** and demonstrates how thoughtful tuning improves operational efficiency.

---

## MITRE ATT&CK Mapping
- **Tactic:** Execution (TA0002)
- **Technique:** T1059.001 – Command and Scripting Interpreter: PowerShell

---

## Baseline Detection Problem
The baseline detection triggers on PowerShell executions using:

- `-ExecutionPolicy Bypass`
- `powershell.exe` process creation

### Issues with the Baseline Alert
- High false positive rate
- No parent process context
- No distinction between obfuscated and transparent execution
- No consideration of integrity level or user interaction
- Benign automation treated as potential compromise

As a result, SOC analysts must repeatedly investigate **legitimate user scripts**, reducing confidence in the alert.

---

## False Positive Patterns Identified
Analysis of alert data revealed common benign patterns:

- User-initiated execution via `explorer.exe`
- Scripts stored in user directories (Documents, Desktop)
- Clear, readable script names
- Use of `-File` parameter rather than inline commands
- Medium integrity (non-elevated) execution
- Predictable, regular execution timing

These patterns strongly indicate **legitimate user or administrative activity**, not attacker behavior.

---

## Detection Engineering Improvements
The tuned detection introduces **contextual enrichment** and **indicator correlation** to improve signal quality.

Key improvements include:

- **Parent process validation**
  - Differentiates GUI-initiated execution from macro or service-based execution
- **Obfuscation and encoding detection**
  - Flags `-EncodedCommand`, inline execution, and hidden windows
- **Execution context awareness**
  - Considers integrity level and privilege
- **Severity differentiation**
  - Assigns higher severity only when multiple suspicious indicators are present

The tuned logic prioritises **confidence over volume**, allowing analysts to focus on meaningful alerts.

---

## Outcome
After tuning:

- False positives from benign automation are significantly reduced
- Malicious PowerShell behavior is more clearly surfaced
- Analyst investigation time is reduced
- Escalation decisions are faster and more consistent
- Alert trustworthiness is improved

This reflects how detection engineering directly improves **SOC effectiveness**, not just detection coverage.

---

## Files in This Scenario
- `baseline-detection.spl` – Original noisy detection logic
- `tuned-detection.spl` – Improved detection with contextual logic
- `false-positive-analysis.md` – Documentation of benign patterns
- `tuning-rationale.md` – Justification for detection changes
- `screenshots/` – Visual evidence of before/after alert behavior

---

## Key Takeaways
- PowerShell execution alone is not malicious
- Context is more valuable than single indicators
- Good detections reduce analyst workload without hiding risk
- Detection engineering is a continuous, evidence-driven process
- SOC efficiency improves when alerts are designed with escalation in mind

---

**Scenario Status:** Completed  
**Project:** Detection-Engineering-Improvement  
**Author:** Marshall
