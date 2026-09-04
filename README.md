# AWS AI Security Hardening Lab

A controlled AWS security assessment and remediation project that
intentionally introduces common cloud security misconfigurations and
Generative-AI workload risks, detects them with a custom Python/Boto3
scanner, applies hardening measures, and verifies the final secure
state.

**Built for the Seconize Technologies DevSecOps Internship screening
assignment.**

------------------------------------------------------------------------

## Table of Contents

-   [Overview](#overview)
-   [Objectives](#objectives)
-   [Results](#results)
-   [Assignment Requirement Mapping](#assignment-requirement-mapping)
-   [Technology Stack](#technology-stack)
-   [Architecture](#architecture)
-   [Project Structure](#project-structure)
-   [Security Assessment Scanner](#security-assessment-scanner)
-   [Security Checks](#security-checks)
    -   [IAM](#iam-security-checks)
    -   [S3](#s3-security-checks)
    -   [Network](#network-security-checks)
    -   [Secrets Management](#secrets-management)
    -   [Logging](#logging-and-monitoring)
    -   [Generative-AI Security](#generative-ai-security)
    -   [Encryption](#encryption)
-   [Vulnerable-to-Secure Workflow](#vulnerable-to-secure-workflow)
-   [Quick Start](#quick-start)
-   [Running the Scanner](#running-the-scanner)
-   [Evidence and Reports](#evidence-and-reports)
-   [Security Standards and
    References](#security-standards-and-references)
-   [Cross-Platform Support](#cross-platform-support)
-   [Cross-Account Scanning](#cross-account-scanning)
-   [Final Submission Checklist](#final-submission-checklist)
-   [Limitations](#limitations)
-   [Author](#author)

------------------------------------------------------------------------

## Overview

The project demonstrates a complete security-hardening lifecycle:

``` text
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

The final assessment validates **14 security controls** across:

-   IAM
-   Amazon S3
-   EC2 and network exposure
-   Secrets Manager
-   AWS CloudTrail
-   Generative-AI workload security
-   EBS encryption

The scanner is designed to identify the affected resource, issue,
severity, impact, remediation guidance, and evidence for each finding.

> **Important:** A final PASS result validates the defined controls
> implemented in this laboratory. It does not certify that an entire AWS
> account is secure.

------------------------------------------------------------------------

## Objectives

1.  Identify security misconfigurations in an AWS environment.
2.  Demonstrate the security impact of each vulnerability.
3.  Develop a modular Python-based automated security assessment
    scanner.
4.  Detect traditional AWS security issues and Generative-AI security
    risks.
5.  Apply appropriate AWS security remediations.
6.  Re-run the scanner to independently verify remediation.
7.  Maintain evidence of vulnerable and hardened states.
8.  Document findings, impact, remediation, architecture, and
    limitations.

------------------------------------------------------------------------

## Results

  Metric              Baseline    Final
  ----------------- ---------- --------
  Security checks           13   **14**
  Passed                     0   **14**
  Failed                **13**    **0**

The baseline contained **13 intentionally introduced findings**. EBS
encryption was subsequently added as an additional control, making the
final assessment **14 checks**.

### Final Scan

``` text
==============================================================
AWS SECURITY HARDENING LAB - SECURITY SCAN
==============================================================
Total checks : 14
Failed       : 0
Passed       : 14
```

The final workflow is:

**Vulnerable → Detect → Remediate → Re-assess → Secure**

------------------------------------------------------------------------

## Assignment Requirement Mapping

  -----------------------------------------------------------------------
  Assignment Requirement              Implementation
  ----------------------------------- -----------------------------------
  Create an intentionally vulnerable  13 baseline findings across IAM,
  AWS environment with at least 10    S3, networking, secrets, logging,
  issues                              and AI security

  Cover multiple AWS security areas   IAM, S3, Security Groups, EC2,
                                      Secrets Manager, CloudTrail, EBS,
                                      AI workload security

  Research AI/ML and Generative-AI    AI workload security risks are
  security                            documented and modeled in the
                                      project

  Identify 2--3 AI-related issues     AI-01, AI-02 and AI-03

  Build a security assessment tool    Modular Python scanner using Boto3

  Detect traditional AWS issues       IAM, S3, network, secrets, logging
                                      and encryption checks

  Detect AI security issues           Dedicated AI security check module

  Report affected resource            Findings identify the relevant
                                      resource

  Report issue and severity           Each finding includes a unique ID,
                                      issue and severity

  Report impact                       Each finding includes potential
                                      security/business impact

  Recommend remediation               Findings include remediation
                                      guidance

  Remediate identified issues         Secure policies, infrastructure
                                      changes and configuration changes

  Remediate AI security issues        Least-privilege AI permissions,
                                      restricted data access and
                                      application security controls

  Validate remediation                Baseline and final scans use the
                                      same scanner

  Demonstrate vulnerable → secure     Vulnerable Environment → Detection
  workflow                            → Remediation → Re-assessment →
                                      Secure Environment

  Provide before-and-after results    Baseline 13 failures and final 14
                                      passes

  Provide source code and IaC         Python scanner, Terraform, policies
                                      and remediation files

  Provide documentation               README, security findings and AI
                                      security documentation

  Provide evidence                    Evidence and machine-readable
                                      reports are stored in the
                                      repository
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## Technology Stack

  -----------------------------------------------------------------------
  Layer                   Technology              Purpose
  ----------------------- ----------------------- -----------------------
  Cloud platform          AWS                     Target security
                                                  environment

  Compute                 Amazon EC2              AI workload host

  Storage                 Amazon S3               Application data

  Identity                AWS IAM                 Workload permissions
                                                  and trust

  Secrets                 AWS Secrets Manager     Secure credential
                                                  storage

  Logging                 AWS CloudTrail          API/account activity
                                                  auditing

  Encryption              Amazon EBS              Data-at-rest protection

  Scanner                 Python 3                Security assessment
                                                  logic

  AWS SDK                 Boto3                   Programmatic AWS
                                                  configuration access

  Manual operations       AWS CLI                 AWS inspection,
                                                  remediation and
                                                  validation

  Infrastructure as Code  Terraform               Repeatable vulnerable
                                                  environment deployment

  Isolation               Python `.venv`          Dependency isolation
  -----------------------------------------------------------------------

The scanner itself uses **Boto3** and does not depend on the AWS CLI.

------------------------------------------------------------------------

## Architecture

``` text
                         AWS ACCOUNT
                              |
                    +---------+---------+
                    |                   |
              VPC / EC2             AWS Services
                    |             /      |       \
             Private Subnet      S3     IAM    Secrets Manager
                    |                    |
              Hardened EC2          Workload Roles
                    |
               Encrypted EBS

                    |
              AWS CloudTrail
                    |
                    v
          API / Configuration Evidence

                    ^
                    |
             Python + Boto3
          Security Assessment Scanner
                    |
          +---------+---------+
          |                   |
     PASS / FAIL          JSON Report
                           +
                       Text Evidence
```

The hardened workload runs in a private subnet without a public IPv4
address. Network, identity, storage, secrets, logging and AI-related
controls are assessed independently.

------------------------------------------------------------------------

## Project Structure

``` text
AWS-AI-Security-Hardening-Lab/
│
├── scanner/
│   ├── __init__.py
│   ├── scanner.py
│   ├── requirements.txt
│   ├── resource_discovery.py
│   └── checks/
│       ├── __init__.py
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
│   ├── application.env.vulnerable
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
│   └── final-scan.json
│
├── docs/
│   ├── security-findings.md
│   ├── ai-security-findings.md
│   └── ai-security-research.md
│
└── terraform/
```

### Resource Discovery

`scanner/resource_discovery.py` dynamically discovers project resources
using project-specific tags and AWS resource properties.

This reduces dependence on hard-coded resource IDs and makes the scanner
more portable when resource identifiers change.

------------------------------------------------------------------------

## Security Assessment Scanner

The scanner entry point is:

``` text
scanner/scanner.py
```

It loads the service-specific check modules, discovers the relevant lab
resources and aggregates the findings.

Each finding follows a structured format:

``` json
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

This makes the output suitable for:

-   human review
-   evidence collection
-   JSON processing
-   future CI/CD integration
-   future dashboards or security gates

### Scanner Design Principles

The scanner follows four main principles:

1.  **Least privilege**
2.  **Secure-by-default configuration**
3.  **Explicit evidence**
4.  **Dynamic resource discovery**

The scanner performs read-oriented configuration assessment. Remediation
is kept separate from detection.

------------------------------------------------------------------------

# Security Checks

## IAM Security Checks

  ----------------------------------------------------------------------------
  Check             Vulnerability          Risk              Remediation
  ----------------- ---------------------- ----------------- -----------------
  `IAM-01`          Excessive application  Compromised role  Replace
                    role permissions       could perform     unrestricted
                                           unauthorized AWS  permissions with
                                           actions           least privilege

  `IAM-02`          IAM                    Workload could    Remove
                    privilege-escalation   potentially       unnecessary
                    permissions            modify            IAM-modifying
                                           permissions or    permissions
                                           escalate          
                                           privileges        

  `IAM-03`          Overly permissive      Unintended        Restrict trust to
                    trust relationship     principals could  intended
                                           assume the role   principals
  ----------------------------------------------------------------------------

The scanner specifically detects unrestricted combinations such as:

``` text
Action: *
Resource: *
```

------------------------------------------------------------------------

## S3 Security Checks

  -----------------------------------------------------------------------------
  Check             Vulnerability     Risk              Remediation
  ----------------- ----------------- ----------------- -----------------------
  `S3-01`           Public            Unauthenticated   Remove public Allow
                    application data  users could       access
                                      access            
                                      application data  

  `S3-02`           Public Access     Bucket            Enable all four Public
                    Block disabled    configuration     Access Block controls
                                      could             
                                      accidentally      
                                      expose objects    

  `S3-03`           HTTPS not         Requests could    Add
                    enforced          use insecure      `aws:SecureTransport`
                                      transport         deny condition
  -----------------------------------------------------------------------------

The hardened application bucket is restricted to authorized access and
secure transport.

------------------------------------------------------------------------

## Network Security Checks

  ----------------------------------------------------------------------------
  Check             Vulnerability      Risk                  Remediation
  ----------------- ------------------ --------------------- -----------------
  `NET-01`          Internet-exposed   Increased brute-force Remove
                    SSH                and                   Internet-wide
                                       unauthorized-access   TCP/22 access
                                       surface               

  `NET-02`          Public EC2         Workload directly     Run the hardened
                    exposure           reachable from the    workload in a
                                       Internet              private subnet
                                                             with no public
                                                             IPv4
  ----------------------------------------------------------------------------

The final hardened EC2 workload has:

-   private subnet placement
-   private IPv4 address
-   no public IPv4 address
-   no Internet-wide SSH rule

------------------------------------------------------------------------

## Secrets Management

  -----------------------------------------------------------------------
  Check             Vulnerability     Risk              Remediation
  ----------------- ----------------- ----------------- -----------------
  `SEC-01`          Hard-coded        Credentials could Use AWS Secrets
                    application       leak through      Manager
                    credentials       source, backups   
                                      or commits        

  -----------------------------------------------------------------------

The vulnerable configuration is preserved separately as:

``` text
insecure-app-config/application.env.vulnerable
```

It contains **dummy laboratory values only**.

The active configuration uses a Secrets Manager reference instead of
storing credential material directly:

``` env
APP_PASSWORD_FROM_SECRETS_MANAGER=true
AWS_CREDENTIALS_FROM_SECRETS_MANAGER=true
SECRET_NAME=AI-Security-Lab-Dummy-Credential
```

The scanner does not retrieve or print the secret value.

------------------------------------------------------------------------

## Logging and Monitoring

### `LOG-01` --- CloudTrail Security Configuration

The scanner validates:

-   CloudTrail availability
-   active logging
-   multi-region configuration
-   S3 log destination

CloudTrail provides an audit trail of AWS API/account activity,
supporting security investigation and incident response.

------------------------------------------------------------------------

## Generative-AI Security

The AI component models the security architecture surrounding a
cloud-hosted Generative-AI workload using AWS services such as Amazon
Bedrock.

**This project does not claim to deploy a production Bedrock model or a
production Bedrock Guardrail.**

The focus is on the infrastructure and application security controls
surrounding an AI workload.

  -------------------------------------------------------------------------------
  Check             Vulnerability     Risk                      Remediation
  ----------------- ----------------- ------------------------- -----------------
  `AI-01`           Excessive AI      A compromised/manipulated Apply
                    workload          workload could access     least-privilege
                    permissions       unnecessary AWS resources IAM

  `AI-02`           Excessive AI data Unnecessary application   Restrict access
                    access            data could be exposed to  to the required
                                      the workload              object

  `AI-03`           Missing AI        Prompt injection, unsafe  Enable required
                    input/output      output and sensitive-data application
                    controls          exposure risks            security controls
  -------------------------------------------------------------------------------

### AI-01 --- Workload Permissions

The scanner detects unrestricted:

``` text
Action: *
Resource: *
```

permissions attached to the AI workload role.

The hardened policy restricts the workload to required actions and
resources.

### AI-02 --- Data Access

The vulnerable configuration permits broad S3 access.

The hardened configuration restricts access to the required application
object rather than the entire bucket.

### AI-03 --- Application Controls

The scanner validates these five local configuration controls:

``` text
input_validation
prompt_injection_detection
output_validation
sensitive_data_filtering
guardrails_enabled
```

These checks are configuration-oriented and do not claim a deployed
production AI guardrail.

------------------------------------------------------------------------

## Encryption

### `ENC-01` --- EBS Encryption

The scanner identifies the EC2 root device and checks the associated EBS
volume.

The hardened root volume is encrypted.

The remediation workflow was:

``` text
Unencrypted Volume
       ↓
Snapshot
       ↓
Encrypted Snapshot Copy
       ↓
New Encrypted Volume
       ↓
Attach as Root Device
       ↓
Verify Encryption
       ↓
Re-run Scanner
```

This approach is used because an existing EBS volume cannot simply be
switched from unencrypted to encrypted in place.

------------------------------------------------------------------------

# Vulnerable-to-Secure Workflow

## Phase 1 --- Vulnerable State

The lab intentionally introduces conditions such as:

-   unrestricted IAM permissions
-   weak IAM trust
-   public S3 access
-   disabled S3 Public Access Block
-   missing HTTPS enforcement
-   Internet-wide SSH exposure
-   public EC2 addressing
-   hard-coded application credentials
-   weak CloudTrail configuration
-   excessive AI workload permissions
-   excessive AI data access
-   disabled AI application controls
-   unencrypted EBS storage

## Phase 2 --- Baseline Detection

The Python/Boto3 scanner identifies the insecure states and records
structured findings.

## Phase 3 --- Remediation

Security controls are applied using:

-   least-privilege IAM policies
-   restricted trust relationships
-   S3 Public Access Block
-   HTTPS enforcement
-   private EC2 architecture
-   Secrets Manager
-   CloudTrail hardening
-   AI least-privilege permissions
-   restricted AI data access
-   AI input/output controls
-   EBS encryption

## Phase 4 --- Re-assessment

The **same scanner** is executed again.

No manual override is used to mark checks as passed.

## Phase 5 --- Secure State

``` text
14 checks
0 failures
14 passes
```

------------------------------------------------------------------------

# Quick Start

## Prerequisites

-   Python 3.9+
-   AWS CLI
-   Terraform
-   Git
-   AWS account with appropriate permissions

Verify:

``` bash
python --version
aws --version
terraform --version
git --version
```

## 1. Clone the Repository

``` bash
git clone https://github.com/sthuthi2002/AWS-AI-Security-Hardening-Lab.git
cd AWS-AI-Security-Hardening-Lab
```

## 2. Create and Activate the Python Environment

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows:

``` powershell
python -m venv .venv
.venv\Scripts\activate
```

## 3. Install Scanner Dependencies

The dependency file is inside the scanner directory:

``` bash
pip install -r scanner/requirements.txt
```

> **Important:** The correct path is `scanner/requirements.txt`, not
> `requirements.txt` at the repository root.

## 4. Configure AWS Authentication

``` bash
aws configure
aws sts get-caller-identity
```

Do not commit AWS credentials or `.aws` credential files to the
repository.

The scanner uses Boto3's AWS credential provider chain and does not
require AWS CLI commands to perform its checks.

## 5. Deploy the Vulnerable Environment

``` bash
cd terraform
terraform init
terraform plan
terraform apply
cd ..
```

> ⚠️ **Warning:** The Terraform configuration intentionally contains
> insecure settings for educational security testing. Do not deploy it
> into a production AWS account.

## 6. Run the Baseline Assessment

``` bash
python -m scanner.scanner
```

Save or review the baseline evidence under:

``` text
evidence/baseline/
reports/
```

## 7. Apply Remediation

Use the remediation configurations and documented AWS changes under:

``` text
remediation/
```

These cover IAM, S3, networking, secrets, CloudTrail, AI permissions, AI
data access, AI application controls and encryption.

## 8. Re-run the Scanner

``` bash
python -m scanner.scanner
```

Expected hardened result:

``` text
Total checks : 14
Failed       : 0
Passed       : 14
```

## 9. Clean Up

If the Terraform-managed environment is no longer required:

``` bash
cd terraform
terraform destroy
```

Always review the Terraform plan before destroying resources.

------------------------------------------------------------------------

# Running the Scanner

From the repository root:

``` bash
source .venv/bin/activate
```

Compile-check the scanner:

``` bash
python -m py_compile scanner/scanner.py
```

Run the full assessment:

``` bash
python -m scanner.scanner
```

The scanner executes:

``` text
IAM
S3
Network
Secrets
CloudTrail
AI
Encryption
```

Final expected output:

``` text
Total checks : 14
Failed       : 0
Passed       : 14
```

------------------------------------------------------------------------

# Evidence and Reports

  -----------------------------------------------------------------------
  Path                                Contents
  ----------------------------------- -----------------------------------
  `evidence/baseline/`                Vulnerable-state scan output and
                                      configuration evidence

  `evidence/remediation/`             Evidence collected during hardening

  `evidence/final/final-scan.txt`     Final scanner output

  `reports/final-scan.json`           Machine-readable final assessment

  `docs/security-findings.md`         Security findings documentation

  `docs/ai-security-findings.md`      AI security findings

  `docs/ai-security-research.md`      AI security research

  `README.md`                         Project documentation
  -----------------------------------------------------------------------

### Final JSON Report

The JSON report contains structured information including:

-   check ID
-   status
-   severity
-   finding
-   affected resource
-   impact
-   remediation
-   evidence

This format can be integrated into future CI/CD security gates.

------------------------------------------------------------------------

# Security Standards and References

The project follows recognized security principles including:

-   Principle of least privilege
-   Defense in depth
-   Secure-by-default configuration
-   Restriction of public access
-   Secrets protection
-   Encryption at rest
-   Network segmentation
-   Logging and monitoring

Relevant security guidance includes:

-   AWS Identity and Access Management best practices
-   Amazon S3 security best practices
-   Amazon EC2 and VPC security guidance
-   AWS Secrets Manager guidance
-   AWS CloudTrail guidance
-   AWS EBS encryption guidance
-   OWASP cloud and application security principles
-   OWASP guidance for Generative-AI application security
-   NIST Cybersecurity Framework concepts
-   CIS AWS Foundations security principles

------------------------------------------------------------------------

# Cross-Account Scanning

The scanner supports secure cross-account assessment using AWS STS `AssumeRole`. A source AWS identity authenticates in one account and temporarily assumes a dedicated scanner role in the target account without storing target-account access keys.

### Cross-Account Flow

```text
Source AWS Account
(terraform-admin)
        |
        | STS AssumeRole
        v
Target AWS Account
AI-Security-CrossAccount-Scanner-Role
        |
        v
Boto3 DEFAULT_SESSION
        |
        v
AWS Resource Discovery + Security Checks
        |
        v
14 PASS / 0 FAIL
```

### Implementation Files

- `scanner/cross_account_auth.py` — handles STS `AssumeRole`, validates source/target identity, and configures temporary Boto3 credentials.
- `scanner/scanner.py` — invokes authentication before running checks and records authentication metadata in the report.
- `scanner/resource_discovery.py` — discovers resources through the active authenticated Boto3 session.
- `scanner/checks/ai_checks.py`
- `scanner/checks/iam_checks.py`
- `scanner/checks/encryption_checks.py`
- `scanner/checks/network_checks.py`
- `scanner/checks/cloudtrail_checks.py`
- `scanner/checks/secrets_checks.py`
- `scanner/checks/s3_checks.py`

The service check modules use `boto3.DEFAULT_SESSION` so all checks operate against the same authenticated account/session established by the cross-account authentication layer.

### Configuration

Cross-account scanning is configured through environment variables. Example:

```env
AWS_REGION=us-east-1
CROSS_ACCOUNT_ENABLED=true
CROSS_ACCOUNT_ROLE_ARN=arn:aws:iam::<TARGET_ACCOUNT_ID>:role/AI-Security-CrossAccount-Scanner-Role
ROLE_SESSION_NAME=AI-Security-Scanner
ROLE_DURATION_SECONDS=3600
```

Replace `<TARGET_ACCOUNT_ID>` with the actual target account ID. Do not type the placeholder literally. Never commit AWS credentials or temporary credential files.

### Security Properties

- Uses temporary STS credentials rather than storing target-account access keys.
- Target-role trust is restricted to the intended source identity.
- Scanner permissions are limited to read-oriented discovery and assessment actions.
- The same scanner code can assess resources in the target account after authentication.
- Authentication details are recorded in the final report for auditability.

### Verified Cross-Account Result

The implementation was validated by authenticating from the source account into the target account and executing the complete security assessment:

```text
Authentication : cross-account
Target account : 115484988521
Total checks   : 14
Failed         : 0
Passed         : 14
```

This confirms that the scanner authenticated to the target account and evaluated the target resources using the assumed role.

------------------------------------------------------------------------

# Cross-Platform Support

The scanner is implemented in Python using Boto3, so the assessment
logic is not tied to a specific operating system.

It can be adapted to run on:

-   Linux
-   Windows
-   macOS
-   Docker containers
-   CI/CD runners

The development environment for this project was an **Ubuntu Linux
virtual machine running through VirtualBox**.

AWS CLI is also cross-platform and was used for AWS inspection,
remediation and validation. It communicates with AWS through
authenticated API requests.

The scanner itself does **not** depend on the AWS CLI; Boto3
communicates directly with AWS services.

### Credential Security

Do not hard-code access keys in source code or configuration.

Prefer:

-   IAM roles
-   temporary credentials
-   environment/credential providers
-   secure CI/CD credential mechanisms
-   AWS Secrets Manager where application secrets are required

------------------------------------------------------------------------

# Final Submission Checklist

-   [x] Source code included
-   [x] Infrastructure-as-Code included
-   [x] At least 10 AWS security issues covered
-   [x] 13 baseline findings
-   [x] 14 final security controls
-   [x] Multiple AWS security domains covered
-   [x] 3 AI security checks included
-   [x] AI risks include impact and remediation
-   [x] Automated Boto3 security scanner included
-   [x] Traditional AWS security issues detected
-   [x] AI security issues detected
-   [x] Findings include severity and affected resources
-   [x] Findings include impact and remediation
-   [x] Security remediation implemented
-   [x] AI security remediation included
-   [x] Baseline assessment available
-   [x] Final assessment available
-   [x] Final result: **14 PASS / 0 FAIL**
-   [x] Before-and-after results documented
-   [x] Evidence stored under `evidence/`
-   [x] JSON report stored under `reports/`
-   [x] Documentation stored under `docs/`
-   [x] Vulnerable configuration contains dummy values only
-   [x] Active application configuration does not contain hard-coded
    credentials
-   [x] Project supports reproducible scanner execution

------------------------------------------------------------------------

# Limitations

This is a security-hardening laboratory, not a production security
platform.

The Generative-AI component models security controls around an AI
workload rather than performing inference through a deployed production
model.

The scanner is scoped to the resources and controls defined for this
laboratory.

A production implementation could additionally integrate:

-   AWS Config
-   AWS Security Hub
-   Amazon GuardDuty
-   Amazon CloudWatch
-   AWS KMS key management
-   VPC endpoint controls
-   centralized logging
-   network segmentation
-   continuous vulnerability assessment
-   automated CI/CD security gates
-   production AI guardrails and model-level testing

A `PASS` result confirms that the specific control is satisfied; it does
not certify that the entire AWS account is secure.

------------------------------------------------------------------------

# Author

**K Sthuthi Nayak**

LinkedIn: [linkedin.com/in/sthuthi22](https://linkedin.com/in/sthuthi22)

Email: sthuthinayak@gmail.com
