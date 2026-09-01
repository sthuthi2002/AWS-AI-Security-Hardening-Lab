# AI Security Research

## Purpose

This document explains the Generative-AI security risks evaluated in the
AWS & AI Security Hardening Lab.

The AI workload in this lab represents a cloud-hosted Generative-AI
application using an AWS managed foundation-model service such as
Amazon Bedrock.

The objective is not to build a production AI application, but to assess
the security controls surrounding an AI workload, including its IAM
permissions, access to application data, and protection of model inputs
and outputs.

---

# 1. AWS Generative-AI Service Scenario

## Amazon Bedrock

Amazon Bedrock is an AWS managed service that provides access to
foundation models for building Generative-AI applications.

A typical application architecture can contain:

Application
    |
    v
Amazon Bedrock
    |
    v
AI workload execution identity
    |
    +---- IAM permissions
    |
    +---- Application data
    |
    +---- Secrets
    |
    +---- Input/output security controls

Because a Generative-AI application may interact with AWS resources and
process application data, the IAM identity and data permissions associated
with the workload must follow least-privilege principles.

The lab therefore evaluates security controls around a representative
Generative-AI workload rather than relying only on the model itself.

---

# 2. AI-01 — Excessive Permissions for AI Workload

**Area:** Generative AI / IAM

**Severity:** Critical

## Security Scenario

A Generative-AI application may require AWS permissions to invoke
services and access only the resources necessary for its operation.

If the AI workload identity is granted unrestricted permissions such as:

    Action: *
    Resource: *

the workload effectively has broad access to the AWS account.

## Risk

If the AI application, execution environment, credentials, or workload
identity is compromised, an attacker could potentially use the same
identity to interact with unrelated AWS resources.

This increases the potential blast radius of a compromise.

## Potential Impact

Possible consequences include:

- Unauthorized access to AWS services
- Access to unrelated application resources
- Data exposure
- Resource modification
- Privilege escalation
- Further compromise of the cloud environment

## Detection

The Python security scanner retrieves the IAM policies attached to the
AI workload role using AWS APIs through boto3.

The scanner examines policy statements and identifies unrestricted
combinations where:

    Effect = Allow
    Action = *
    Resource = *

The finding is reported as AI-01.

## Remediation

Apply least-privilege IAM permissions.

The hardened AI workload policy grants only the AWS permissions required
by the workload instead of unrestricted access.

---

# 3. AI-02 — Excessive Data Access by AI Workload

**Area:** Generative AI / Data Security

**Severity:** High

## Security Scenario

Generative-AI applications frequently process application data as part
of retrieval, analysis, summarization, or decision-support workflows.

An AI workload should only be able to access the data required for its
specific task.

In this lab, the vulnerable configuration allows the AI workload to access
the application S3 bucket broadly.

The vulnerable policy includes:

    s3:GetObject
    s3:ListBucket

against the application bucket and its objects.

## Risk

If the AI workload or application is compromised, excessive data access
could allow information that is not required by the AI workflow to be
retrieved or processed.

This creates a larger data-exposure boundary.

## Potential Impact

Possible consequences include:

- Unauthorized data retrieval
- Sensitive information disclosure
- Privacy exposure
- Data leakage through AI processing
- Increased impact of prompt-injection or application compromise

## Detection

The Python scanner retrieves the IAM policy associated with the AI
workload's data-access policy.

It checks whether the workload can access the application S3 bucket.

The vulnerable configuration is detected as AI-02.

## Remediation

Apply resource-level least privilege.

The hardened policy restricts the AI workload to the specific application
object required by the workflow:

    arn:aws:s3:::ai-security-lab-data-256148542278/application-data.txt

This prevents unnecessary bucket-wide or object-wide access.

---

# 4. AI-03 — Missing Generative-AI Input/Output Security Controls

**Area:** Generative AI Application Security

**Severity:** High

## Security Scenario

Generative-AI applications process untrusted user input and produce
model-generated output.

Unlike traditional applications, AI applications can be influenced by
natural-language instructions and prompt-based attacks.

Security controls are therefore required around both model inputs and
outputs.

The lab evaluates the following controls:

- Input validation
- Prompt-injection detection
- Output validation
- Sensitive-data filtering
- Guardrails

## Prompt Injection

Prompt injection occurs when malicious or unintended instructions are
introduced into model input in an attempt to influence the model's
behavior or bypass application instructions.

For example, an attacker could attempt to manipulate a model into
revealing information that the application should not expose.

## Sensitive Data Leakage

Generative-AI applications may process confidential application data.

Without output filtering and validation, sensitive information could
potentially be returned to users or exposed through generated responses.

## Unsafe Model Output

Model output should not automatically be trusted.

Applications should validate generated content before using it in
downstream systems or returning it to users.

## Detection

The scanner evaluates the AI application's security configuration file:

    insecure-app-config/ai-config.json

The scanner checks whether the following controls are enabled:

    input_validation
    prompt_injection_detection
    output_validation
    sensitive_data_filtering
    guardrails_enabled

If any required control is explicitly disabled, AI-03 is reported as a
failure.

## Remediation

Enable appropriate application-level security controls for Generative-AI
workflows.

The hardened configuration enables:

- Input validation
- Prompt-injection detection
- Output validation
- Sensitive-data filtering
- Guardrails

---

# 5. Relationship Between the Three AI Findings

The three findings protect different layers of the Generative-AI
application.

    AI-03
    Input / Output Security
            |
            v
    +----------------------+
    | Generative-AI App    |
    +----------------------+
            |
            v
    AI-01
    IAM Least Privilege
            |
            v
    AWS Resources
            |
            v
    AI-02
    Data Access Least Privilege

AI-01 limits what the AI workload can do.

AI-02 limits what application data the AI workload can access.

AI-03 protects the interaction between users, the application, and the
Generative-AI model.

Together, these controls reduce the potential impact of a compromised
AI application or manipulated AI interaction.

---

# 6. Why AI Security Is Different

Traditional cloud security focuses heavily on identities,
infrastructure, networks, storage, and application permissions.

Generative-AI applications introduce additional risks because model
behavior can be influenced through natural-language input and because
model output can be generated dynamically.

Therefore, AI security requires both:

1. Traditional cloud security controls
2. AI-specific application and model interaction controls

This lab combines both approaches.

---

# 7. Scanner Implementation

The AI security checks are implemented as a modular Python component:

    scanner/checks/ai_checks.py

The scanner uses boto3 to query AWS IAM resources and Python's JSON
processing capabilities to inspect the application-level AI security
configuration.

The checks produce structured findings containing:

- Finding ID
- Status
- Severity
- Resource
- Evidence
- Impact
- Recommended remediation

This allows the same checks to be executed during the vulnerable
baseline assessment and after remediation.

---

# 8. Final Security State

After remediation, the AI security scanner reports:

    AI-01 = PASS
    AI-02 = PASS
    AI-03 = PASS

This demonstrates that:

- The AI workload uses restricted IAM permissions.
- AI data access is limited to the required application resource.
- Generative-AI input/output security controls are enabled.

The AI controls are therefore evaluated as part of the overall cloud
security posture rather than being treated as an isolated AI feature.
