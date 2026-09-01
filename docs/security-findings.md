# AWS Security Findings

## Purpose

This document defines the intentionally vulnerable AWS environment
for the Seconize DevSecOps Intern screening assignment.

The environment is designed to demonstrate individual security
misconfigurations as well as correlated attack paths.

---

## AWS Findings

### IAM-01 — Excessive Application Role Permissions

**Area:** IAM  
**Severity:** High

The application IAM role is intentionally configured with permissions
broader than required.

**Risk:** A compromised workload may perform unauthorized AWS actions.

**Remediation:** Apply least-privilege permissions limited to the
required AWS actions and resources.

---

### IAM-02 — IAM Privilege Escalation Permissions

**Area:** IAM  
**Severity:** Critical

The vulnerable role contains permissions that could allow an attacker
to modify or obtain additional IAM privileges.

**Risk:** A compromised identity may escalate privileges.

**Remediation:** Remove unnecessary IAM administration and
privilege-escalation permissions.

---

### IAM-03 — Overly Permissive Role Trust Relationship

**Area:** IAM  
**Severity:** Critical

The role trust policy is intentionally broader than required.

**Risk:** An unauthorized principal may be able to assume the role.

**Remediation:** Restrict the trust policy to the specific trusted
principal or service.

---

### S3-01 — Public Application Data

**Area:** S3  
**Severity:** Critical

The application-data bucket is intentionally configured to allow
public object access.

**Risk:** Unauthorized users may retrieve stored application data.

**Remediation:** Remove public access and implement least-privilege
bucket and object permissions.

---

### S3-02 — Public Access Protection Disabled

**Area:** S3  
**Severity:** High

S3 public-access protection controls are intentionally weakened.

**Risk:** Misconfigured bucket policies or ACLs may expose data.

**Remediation:** Enable S3 Block Public Access controls.

---

### S3-03 — HTTPS Not Enforced

**Area:** S3  
**Severity:** Medium

The bucket policy does not explicitly deny insecure transport.

**Risk:** Clients may access the bucket without an explicit TLS
requirement.

**Remediation:** Add a bucket policy condition requiring
aws:SecureTransport=true.

---

### NET-01 — Internet-Exposed SSH

**Area:** Networking  
**Severity:** High

SSH access is intentionally permitted from the entire IPv4 internet.

**Risk:** Increases exposure to automated scanning and unauthorized
access attempts.

**Remediation:** Restrict administrative access to trusted networks
or a controlled management path.

---

### NET-02 — Internet-Facing Application Workload

**Area:** Networking  
**Severity:** High

The application EC2 workload is intentionally deployed with
unnecessary internet exposure.

**Risk:** A vulnerable application may become an entry point into
the AWS environment.

**Remediation:** Place workloads in private subnets where appropriate
and expose only required application endpoints.

---

### SEC-01 — Insecure Application Credential Storage

**Area:** Secrets  
**Severity:** High

A dummy application credential is intentionally stored in an
insecure configuration location.

**Risk:** Credentials may be exposed through source code,
configuration files, or deployment artifacts.

**Remediation:** Store secrets in AWS Secrets Manager or another
approved secret-management system.

---

### LOG-01 — Weak CloudTrail Security Configuration

**Area:** Logging  
**Severity:** High

The lab intentionally uses a CloudTrail configuration that lacks
required security protections.

**Risk:** Reduced visibility and weaker evidence for security
investigations.

**Remediation:** Configure appropriate multi-Region logging,
log-file validation, protected log storage, and monitoring.

---

# Attack Path Correlations

## Attack Path 1 — Internet to AWS Privilege Escalation

NET-02 → IAM-01 → IAM-02

An internet-exposed workload is compromised and its IAM role provides
excessive permissions, including permissions that may facilitate
privilege escalation.

---

## Attack Path 2 — Public Storage Data Exposure

S3-02 → S3-01

Weak public-access protections combined with public object access can
result in unauthorized data exposure.

---

## Attack Path 3 — Unauthorized Role Assumption

IAM-03 → IAM-01 → IAM-02

An overly broad trust relationship can allow an unauthorized principal
to obtain a role whose permissions are already excessive.

