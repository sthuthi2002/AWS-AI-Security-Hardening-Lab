# AI Security Findings

## Purpose

This document defines the intentionally introduced AI/ML and
Generative-AI security risks for the Seconize DevSecOps Intern
AWS & AI Security Hardening assignment.

---

## AI-01 — Excessive Permissions for AI Workload

**Area:** AI Security / IAM  
**Severity:** Critical

The AI workload is associated with permissions broader than required
for its intended application task.

**Risk:** If the AI workload or its execution identity is compromised,
an attacker may use the identity to access or modify unrelated AWS
resources.

**Potential Misuse:** An attacker could abuse the workload identity
to access additional AWS services or resources.

**Security/Business Impact:** Unauthorized access, data exposure,
resource modification, or further compromise of the AWS environment.

**Remediation:** Apply least-privilege IAM permissions specifically
required by the AI workload.

---

## AI-02 — Excessive Data Access by AI Workload

**Area:** AI Security / Data Security  
**Severity:** High

The AI workload is intentionally given access to application data
beyond the minimum data required for its intended task.

**Risk:** Sensitive or unnecessary application data may become
available to an AI processing workflow.

**Potential Misuse:** Compromised prompts, applications, or workload
identities could result in unauthorized retrieval or processing of
application data.

**Security/Business Impact:** Data leakage, privacy exposure, and
loss of confidentiality.

**Remediation:** Restrict AI workload data access using least
privilege, resource-level permissions, and appropriate data
classification controls.

---

## AI-03 — Missing AI Input/Output Security Controls

**Area:** Generative AI Security  
**Severity:** High

The AI application does not implement explicit controls for
malicious inputs, prompt injection, sensitive-data leakage, or
unsafe model output.

**Risk:** An attacker may manipulate application inputs to influence
AI behavior or cause unintended information disclosure.

**Potential Misuse:** Prompt injection or malicious input could cause
the application to ignore intended instructions or expose data
available to the AI workflow.

**Security/Business Impact:** Unauthorized information disclosure,
unsafe application behavior, reputational damage, or business impact.

**Remediation:** Implement input validation, prompt-injection
defenses, output validation, sensitive-data filtering, and
appropriate application-level guardrails.
