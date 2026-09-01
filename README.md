# AWS AI Security Hardening Lab

A security assessment and remediation project that identifies, demonstrates, and remediates common AWS cloud misconfigurations alongside security risks specific to a Generative-AI workload — using a custom Python scanner to detect, fix, and verify issues end-to-end.

Built for the Seconize Technologies DevSecOps Internship screening assignment.

---

## Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Results](#results)
- [Assignment Requirement Mapping](#assignment-requirement-mapping)
- [Tech Stack](#tech-stack)
- [Architecture](#architecture)
- [Security Assessment Scanner](#security-assessment-scanner)
- [Security Checks](#security-checks)
  - [IAM](#iam-security-checks)
  - [S3](#s3-security-checks)
  - [Network](#network-security-checks)
  - [Secrets Management](#secrets-management)
  - [Logging & Monitoring](#logging-and-monitoring)
  - [Generative-AI Security](#generative-ai-security)
  - [Encryption](#encryption)
- [Quick Start](#quick-start)
- [Running the Scanner](#running-the-scanner)
- [Evidence & Reports](#evidence--reports)
- [Security Standards and References](#security-standards-and-references)
- [Submission Evidence](#submission-evidence)
- [Final Submission Checklist](#final-submission-checklist)
- [Vulnerable-to-Secure Workflow](#vulnerable-to-secure-workflow)
- [Limitations](#limitations)
- [Author](#author)

---

## Overview

The project follows a complete security lifecycle:

```
Vulnerable Configuration
        ↓
Baseline Security Assessment
        ↓
Detection
        ↓
Remediation
        ↓
Re-assessment
        ↓
Hardened Configuration
```

The final assessment validates **14 security controls** across IAM, S3, networking, secrets management, logging, Generative-AI security, and encryption.

## Objectives

1. Identify security misconfigurations in an AWS environment
2. Demonstrate the security impact of each vulnerability
3. Develop a Python-based automated security assessment scanner
4. Detect both traditional cloud security issues and Generative-AI security risks
5. Apply appropriate AWS security remediations
6. Re-run the scanner to verify remediation
7. Maintain evidence of both vulnerable and hardened states
8. Document design, findings, impact, and remediation

## Results

| Metric | Baseline Scan | Final Scan |
|---|---:|---:|
| Total checks | 13 | **14** |
| Passed | 0 | **14** |
| Failed | **13** | **0** |

The baseline assessment identified 13 intentionally introduced security misconfigurations across IAM, S3, networking, secrets management, logging, and Generative-AI security.

Encryption was subsequently added as an additional security control. The unencrypted EBS root volume was identified and remediated, bringing the final assessment to 14 checks with 0 failures.

### Final Scan

```
==============================================================
AWS SECURITY HARDENING LAB - SECURITY SCAN
==============================================================
Total checks : 14
Failed       : 0
Passed       : 14
```

Vulnerable → Detect → Remediate → Re-assess → Secure — demonstrated with the same scanner used at every stage.

## Assignment Requirement Mapping

This project was developed to satisfy the requirements of the **DevSecOps Intern – AWS & AI Security Hardening** assignment.

| Assignment Requirement | Implementation in This Project |
|---|---|
| Create an intentionally vulnerable AWS environment with at least 10 security issues | 13 baseline checks across IAM, S3, networking, secrets, and logging; 14 total checks after adding encryption |
| Cover multiple AWS security areas | IAM, S3, Security Groups, Secrets Manager, CloudTrail, EBS encryption, and AI workload security |
| Research AI/ML and Generative AI security risks | Documented realistic AI security risks modeled around a Generative-AI workload architecture |
| Identify 2–3 AI-related security issues | 3 AI security checks: excessive permissions, excessive data access, missing input/output security controls |
| Build a security assessment tool | Modular Python security scanner using `boto3` |
| Detect traditional AWS security issues | Scanner checks IAM, S3, networking, secrets, logging, and encryption configurations |
| Detect AI security issues | Scanner includes dedicated AI security checks |
| Report affected resource | Each finding identifies the affected AWS resource |
| Report issue and severity | Findings include a unique ID, security issue, and severity |
| Report impact | Each finding explains the potential security and business impact |
| Recommend remediation | Each finding includes recommended remediation steps |
| Remediate identified issues | Secure configurations, IAM policies, infrastructure changes, and automation are provided |
| Remediate AI security issues | AI workload permissions and data access are restricted; input/output security controls are modeled |
| Validate remediation | The scanner is executed before and after remediation |
| Demonstrate vulnerable → secure workflow | Vulnerable Environment → Detection → Remediation → Re-assessment → Secure Environment |
| Provide before-and-after results | Baseline (13/13 fail) and final (14/14 pass) results are included in the repository |
| Provide source code and IaC | Source code, Terraform configurations, policies, and remediation files are included |
| Provide documentation | README and supporting documentation are included |
| Provide evidence | Assessment reports and supporting evidence are included under `evidence/` and `reports/` |

## Tech Stack

| Layer | Tool | Why |
|---|---|---|
| Cloud platform | AWS (EC2, S3, IAM, Secrets Manager, CloudTrail, EBS) | Target environment for the lab |
| Scanner language | Python 3 | Easy boto3 integration, JSON handling, modular checks |
| AWS SDK | boto3 | Queries live AWS configuration rather than static files |
| Manual ops | AWS CLI | Inspection, remediation, and evidence collection |
| Isolation | Python virtual environment (`.venv/`) | Keeps project dependencies isolated from system Python |

```bash
source .venv/bin/activate
```

## Architecture

```
AWS-AI-Security-Hardening-Lab/
│
├── scanner/
│   ├── scanner.py
│   ├── requirements.txt
│   └── checks/
│       ├── iam_checks.py
│       ├── s3_checks.py
│       ├── network_checks.py
│       ├── secrets_checks.py
│       ├── cloudtrail_checks.py
│       ├── ai_checks.py
│       └── encryption_checks.py
│
├── insecure-app-config/
│   ├── application.env
│   └── ai-config.json
│
├── remediation/
│   ├── application-secure.env
│   ├── secure-policy.json
│   ├── secure-trust-policy.json
│   ├── secure-bucket-policy.json
│   ├── ai-workload-secure-policy.json
│   ├── ai-data-access-secure-policy.json
│   └── ...
│
├── evidence/
│   ├── baseline/
│   ├── remediation/
│   └── final/
│
├── reports/
│
├── docs/
│   ├── security-findings.md
│   ├── ai-security-findings.md
│   └── ai-security-research.md
│
└── terraform/
```

The scanner is modular by design: each security domain owns its own check module, communicates with AWS exclusively through read-only boto3 calls, and remediation is handled as a separate, explicit step.

## Security Assessment Scanner

The entry point is `scanner/scanner.py`, which imports every category-specific check module and runs `run_all_checks()` to execute and aggregate results.

Each finding is a structured object:

```json
{
  "id": "AI-01",
  "status": "PASS",
  "severity": "Critical",
  "finding": "...",
  "resource": "...",
  "impact": "...",
  "remediation": "...",
  "evidence": "..."
}
```

This structure makes results automatable and CI/CD-ready.

---

## Security Checks

### IAM Security Checks

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `IAM-01` Excessive Application Role Permissions | Role has unrestricted `Action:*` / `Resource:*` | Compromised role could perform unauthorized actions across AWS | Replaced with a least-privilege policy scoped to required permissions |
| `IAM-02` IAM Privilege Escalation Permissions | Role holds IAM-modifying permissions that could enable privilege escalation | Compromised workload could escalate its own privileges | Restricted to minimum required application actions |
| `IAM-03` Overly Permissive Role Trust Relationship | Trust policy allows unintended principals to assume the role | Unauthorized principal could obtain the role's permissions | Trust relationship restricted to the intended principal |

### S3 Security Checks

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `S3-01` Public Application Data | Bucket policy contains a public Allow statement | Sensitive data exposed to unauthenticated internet users | Public Allow access removed; restricted to authorized principals |
| `S3-02` Public Access Protection Disabled | All four S3 Public Access Block controls disabled | Misconfigured policies/ACLs could accidentally expose data | All four Public Access Block controls enabled |
| `S3-03` HTTPS Not Enforced | No `aws:SecureTransport` condition on bucket policy | Traffic could use insecure transport | Deny condition added to reject non-HTTPS requests |

### Network Security Checks

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `NET-01` Internet-Exposed SSH | TCP port 22 open to `0.0.0.0/0` | Increased attack surface for brute-force/unauthorized access | SSH restricted to trusted administrative sources |
| `NET-02` Internet-Facing Application Workload | EC2 instance has a public IPv4 address | Workload directly reachable from the internet | Hardened instance runs with private IP only, no public IP |

### Secrets Management

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `SEC-01` Insecure Application Credential Storage | Plaintext `APP_PASSWORD`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` in app config | Credentials exposed via source, backups, or accidental commits | Migrated to AWS Secrets Manager (`AI-Security-Lab-Dummy-Credential`); app config no longer holds real values |

### Logging and Monitoring

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `LOG-01` Weak CloudTrail Security Configuration | Trail not multi-region; log file validation disabled | Security events in other regions missed; log integrity unverifiable | Enabled `IsMultiRegionTrail` and `LogFileValidationEnabled` |

CloudTrail records AWS API/account activity — what action, which principal, when, and against which resource — making it central to auditing and incident response.

### Generative-AI Security

The AI portion of the project models the security architecture of a cloud-hosted Generative-AI application using an AWS-managed foundation-model service such as **Amazon Bedrock**. It does not deploy a production Bedrock model — the focus is on the security controls surrounding an AI workload.

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `AI-01` Excessive Permissions for Generative-AI Workload | AI workload IAM policy has unrestricted `Action:*` / `Resource:*` | A compromised or manipulated AI workload could gain unauthorized AWS access | Replaced with a least-privilege policy granting only required access |
| `AI-02` Excessive Data Access by Generative-AI Workload | AI workload has `s3:GetObject` / `s3:ListBucket` across the full application bucket | Unnecessary data exposure to the model; retrieved data can influence model output | Scoped to the single required object: `arn:aws:s3:::ai-security-lab-data-256148542278/application-data.txt` |
| `AI-03` Generative-AI Input/Output Security Controls | Application-level AI safeguards disabled | Exposure to prompt injection, malicious input, unsafe output, sensitive data disclosure | All five controls enabled: `input_validation`, `prompt_injection_detection`, `output_validation`, `sensitive_data_filtering`, `guardrails_enabled` |

`AI-03` is detected by reading `insecure-app-config/ai-config.json` and checking whether any required control is explicitly disabled.

### Encryption

| Check | Vulnerability | Risk | Remediation |
|---|---|---|---|
| `ENC-01` Unencrypted EBS Volume | EC2 root EBS volume not encrypted | Data at rest unprotected | Migrated to an encrypted volume (`vol-069076c670e9b82fd`), `Encrypted = True` |

**Why a migration, not an in-place change:** EBS encryption can't be toggled on an existing volume. The remediation path was: snapshot the unencrypted volume → copy the snapshot with encryption enabled → create a new encrypted volume → stop the instance → detach the original root volume → attach the encrypted volume as `/dev/xvda` → restart → verify encryption → re-run the scanner. This mirrors a realistic production remediation rather than just flipping a flag.

---

## Quick Start

### Prerequisites

- Python 3.9+
- AWS CLI
- Terraform
- Git
- AWS account with appropriate permissions

```bash
python --version
aws --version
terraform --version
git --version
```

### 1. Clone the Repository

```bash
git clone https://github.com/sthuthi2002/AWS-AI-Security-Hardening-Lab.git
cd AWS-AI-Security-Hardening-Lab
```

### 2. Configure AWS Credentials

```bash
aws configure
aws sts get-caller-identity
```

> **Security Note:** Do not commit AWS access keys, secret keys, `.aws` credential files, or other sensitive information to the repository.

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Deploy the Vulnerable Environment

```bash
cd terraform
terraform init
terraform plan
terraform apply
cd ..
```

> ⚠️ **Warning:** This lab intentionally contains insecure configurations for security testing and educational purposes. Do not use these configurations in a production AWS environment.

### 5. Run the Baseline Security Assessment

```bash
python -m scanner.scanner
```

Save or review the baseline results under `evidence/` and `reports/`.

### 6. Apply Security Remediation

Apply the remediation configurations and scripts under `remediation/`, covering IAM, S3, network, secrets, CloudTrail, AI workload permissions, AI data access, AI input/output controls, and encryption.

### 7. Re-run the Security Assessment

```bash
python -m scanner.scanner
```

Compare results against the baseline to confirm remediation.

### 8. Review the Evidence

```text
evidence/
reports/
docs/
```

### 9. Clean Up AWS Resources

```bash
cd terraform
terraform destroy
```

> ⚠️ Always verify the resources Terraform plans to destroy before confirming.

## Running the Scanner


```bash
# Activate the virtual environment
source .venv/bin/activate

# Compile-check
python -m py_compile scanner/scanner.py

# Run the full assessment
python -m scanner.scanner
```

The scanner runs IAM, S3, Network, Secrets, CloudTrail, AI, and Encryption checks in sequence. Expected output on the hardened environment:

```
Total checks : 14
Failed       : 0
Passed       : 14
```

## Evidence & Reports

| Path | Contents |
|---|---|
| `evidence/baseline/` | Baseline scan, IAM/trust/bucket policies, Public Access Block config, security-group config, EC2 config, CloudTrail config, insecure credentials |
| `evidence/remediation/` | Evidence collected during remediation |
| `evidence/final/final-scan.txt` | Final scanner output (14/14 pass) |
| `reports/final-scan.json` | Machine-readable final report — timestamp, totals, individual findings |

## Security Standards and References

The security checks and remediation recommendations follow recognized cloud security principles and AWS security best practices:

- Applying the principle of least privilege
- Avoiding overly permissive IAM policies
- Restricting public access to sensitive resources
- Enabling logging and monitoring
- Protecting secrets and credentials
- Encrypting sensitive data
- Restricting network exposure
- Implementing defense in depth

**CIS AWS Foundations**

| Security Area | Security Principle |
|---|---|
| IAM | Avoid overly permissive users, roles, and policies |
| S3 | Prevent unnecessary public access to storage |
| Logging | Enable audit logging and monitoring |
| Encryption | Protect data using appropriate encryption controls |
| Network | Restrict unnecessary access from the internet |

**OWASP Cloud and Application Security** — improper access control, excessive permissions, exposure of sensitive data, improper secrets management, security misconfiguration, insufficient logging and monitoring.

**AI and Generative AI Security**

| AI Security Risk | Potential Impact | Security Control |
|---|---|---|
| Excessive IAM permissions | AI workload may access or modify unnecessary AWS resources | Apply least-privilege IAM permissions |
| Excessive data access | Sensitive data may be exposed to the AI workload | Restrict access to required resources only |
| Prompt injection / malicious input | AI behavior may be manipulated by untrusted input | Implement input validation and security controls |
| Unsafe AI output | Sensitive or unsafe information may be exposed | Implement output validation and filtering |
| Sensitive data exposure | Confidential data may be exposed through AI applications | Apply data access controls and data protection mechanisms |

> **AI Scenario:** This lab models the security architecture surrounding a Generative-AI workload using AWS services. The focus is on securing the infrastructure, IAM permissions, data access, and application input/output controls associated with an AI workload. The project does not represent a production AI deployment — the AI-related scenarios are designed for security assessment and educational purposes.

## Submission Evidence

This repository includes evidence demonstrating the complete security hardening lifecycle:

```text
Vulnerable Environment → Baseline Assessment → Security Findings → Remediation → Re-assessment → Secure Environment
```

| Evidence | Location |
|---|---|
| Vulnerable environment assessment & security findings | `evidence/baseline/` |
| Remediation evidence | `evidence/remediation/` |
| Final assessment | `evidence/final/` |
| Structured scanner reports | `reports/` |
| AI security findings | `docs/` |
| Architecture and project documentation | `README.md` |

**Recommended screenshots** to include for evaluators:

| Screenshot | Suggested Filename |
|---|---|
| Baseline scanner output (failed findings) | `evidence/baseline/baseline-scan.png` |
| Example findings (public S3, permissive IAM role, open Security Group, exposed secrets) | `evidence/baseline/security-findings.png` |
| Remediation process (Terraform/IAM/S3/Security Group changes) | `evidence/remediation/remediation-process.png` |
| Final scanner output (0 failed, 14 passed) | `evidence/final/final-scan.png` |

## Final Submission Checklist

- [x] Source code available
- [x] Infrastructure-as-Code included
- [x] At least 10 AWS security issues covered (13 baseline)
- [x] Multiple AWS security domains covered
- [x] 2–3 AI security risks included
- [x] AI risks include impact and remediation
- [x] Automated security assessment tool included
- [x] Traditional AWS security issues detected
- [x] AI security issues detected
- [x] Findings include severity and affected resources
- [x] Findings include impact and remediation
- [x] Security remediation implemented
- [x] AI security remediation included
- [x] Baseline assessment available (13/13 fail)
- [x] Re-assessment available (14/14 pass)
- [x] Before-and-after results documented
- [x] README and design documentation included
- [x] Screenshots 
- [x] Baseline and final assessment differences clearly explained (13 → 14 checks, encryption added)



## Vulnerable-to-Secure Workflow

**Phase 1 — Vulnerable State:** excessive IAM permissions, weak trust relationships, public S3 config, missing Public Access Block/HTTPS enforcement, internet-exposed SSH, public EC2 address, hardcoded credentials, weak CloudTrail config, over-permissioned AI workload, excessive AI data access, missing AI security controls, unencrypted EBS storage.

**Phase 2 — Baseline Detection:** Python scanner inspects the environment and flags all of the above.

**Phase 3 — Remediation:** least-privilege IAM, restricted trust relationships, S3 Public Access Block, HTTPS enforcement, private EC2 configuration, Secrets Manager, CloudTrail hardening, AI least privilege + data-access restriction + input/output controls, EBS encryption.

**Phase 4 — Re-assessment:** the same scanner is executed again — no new tooling, no manual override.

**Phase 5 — Secure State:** **14 checks, 0 failures, 14 passes.**

## Limitations

This is a security-hardening lab, not a production security platform. The Generative-AI checks model security controls around an AI workload rather than performing inference through a deployed production model, and the scanner is scoped to this lab's specific resources.

Production environments would typically add: AWS Config, Security Hub, GuardDuty, CloudWatch monitoring, KMS key management, VPC endpoint controls, network segmentation, centralized log analysis, and automated CI/CD security gates.

A `PASS` result confirms the specific control is satisfied — it does not certify that the entire AWS account is secure.

## Author

**K Sthuthi Nayak**
[linkedin.com/in/sthuthi22](https://linkedin.com/in/sthuthi22) · sthuthinayak@gmail.com
