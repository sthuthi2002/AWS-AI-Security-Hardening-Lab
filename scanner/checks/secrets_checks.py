import boto3
import os
import sys
from pathlib import Path


# ============================================================
# Make project root available when running directly
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ============================================================
# Configuration
# ============================================================

CREDENTIAL_FILE = (
    Path(PROJECT_ROOT)
    / "insecure-app-config"
    / "application.env"
)

SECRET_NAME = "AI-Security-Lab-Dummy-Credential"


# ============================================================
# AWS Client
# ============================================================

def get_secretsmanager_client():
    return boto3.DEFAULT_SESSION.client(
        "secretsmanager"
    )


# ============================================================
# SEC-01
# Insecure Application Credential Storage
# ============================================================

def check_sec_01():
    """
    SEC-01:

    Detect insecure storage of application credentials.

    Secure state:

        - Application does not contain hard-coded credentials.
        - Required secret exists in AWS Secrets Manager.
        - Secret is not scheduled for deletion.

    Vulnerable state:

        - Credentials are present in application.env.
        - OR the expected Secrets Manager secret is missing.
    """

    secretsmanager = get_secretsmanager_client()

    # --------------------------------------------------------
    # Check local application configuration
    # --------------------------------------------------------

    sensitive_patterns = [
        "APP_PASSWORD=",
        "AWS_ACCESS_KEY_ID=",
        "AWS_SECRET_ACCESS_KEY=",
    ]

    found_credentials = []

    if CREDENTIAL_FILE.exists():

        try:

            content = CREDENTIAL_FILE.read_text()

            found_credentials = [
                pattern
                for pattern in sensitive_patterns
                if pattern in content
            ]

        except Exception as e:

            return {
                "id": "SEC-01",
                "status": "ERROR",
                "severity": "High",
                "finding": (
                    "Insecure Application "
                    "Credential Storage"
                ),
                "resource": str(CREDENTIAL_FILE),
                "impact": (
                    "The scanner could not inspect the "
                    "application credential configuration."
                ),
                "remediation": (
                    "Verify that application configuration "
                    "files can be safely inspected."
                ),
                "evidence": str(e),
            }

    # --------------------------------------------------------
    # If hard-coded credentials exist, FAIL immediately
    # --------------------------------------------------------

    if found_credentials:

        return {
            "id": "SEC-01",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Insecure Application "
                "Credential Storage"
            ),
            "resource": str(CREDENTIAL_FILE),
            "impact": (
                "Hardcoded passwords or AWS credentials "
                "can be exposed through source code, "
                "configuration files, backups, or "
                "unauthorized access to the application "
                "environment."
            ),
            "remediation": (
                "Move sensitive credentials into AWS "
                "Secrets Manager and remove credential "
                "values from application configuration files."
            ),
            "evidence": (
                "Sensitive credential patterns detected "
                f"in {CREDENTIAL_FILE}: "
                + ", ".join(found_credentials)
            ),
        }

    # --------------------------------------------------------
    # Check AWS Secrets Manager
    # --------------------------------------------------------

    try:

        response = secretsmanager.describe_secret(
            SecretId=SECRET_NAME
        )

    except secretsmanager.exceptions.ResourceNotFoundException:

        return {
            "id": "SEC-01",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Insecure Application "
                "Credential Storage"
            ),
            "resource": SECRET_NAME,
            "impact": (
                "The expected application credential "
                "secret does not exist in AWS Secrets Manager."
            ),
            "remediation": (
                "Create the application credential in "
                "AWS Secrets Manager and retrieve it at "
                "runtime instead of storing it in "
                "application configuration."
            ),
            "evidence": (
                f"AWS Secrets Manager secret "
                f"{SECRET_NAME} was not found."
            ),
        }

    except secretsmanager.exceptions.ClientError as e:

        return {
            "id": "SEC-01",
            "status": "ERROR",
            "severity": "High",
            "finding": (
                "Unable to Inspect "
                "AWS Secrets Manager"
            ),
            "resource": SECRET_NAME,
            "impact": (
                "The scanner could not determine whether "
                "the application's credential secret exists."
            ),
            "remediation": (
                "Verify IAM permissions for "
                "secretsmanager:DescribeSecret."
            ),
            "evidence": str(e),
        }

    except Exception as e:

        return {
            "id": "SEC-01",
            "status": "ERROR",
            "severity": "High",
            "finding": (
                "Unable to Inspect "
                "AWS Secrets Manager"
            ),
            "resource": SECRET_NAME,
            "impact": (
                "The scanner encountered an unexpected "
                "error while inspecting the secret."
            ),
            "remediation": (
                "Verify AWS credentials, region, and "
                "Secrets Manager permissions."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Check deletion status
    # --------------------------------------------------------

    deletion_date = response.get(
        "DeletedDate"
    )

    if deletion_date:

        return {
            "id": "SEC-01",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Application Credential Secret "
                "Scheduled for Deletion"
            ),
            "resource": SECRET_NAME,
            "impact": (
                "The application depends on a secret that "
                "is scheduled for deletion and may become "
                "unavailable."
            ),
            "remediation": (
                "Restore the secret or create a replacement "
                "secret before application credentials "
                "become unavailable."
            ),
            "evidence": (
                f"Secret {SECRET_NAME} has a DeletedDate "
                f"of {deletion_date}."
            ),
        }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    arn = response.get(
        "ARN",
        SECRET_NAME
    )

    return {
        "id": "SEC-01",
        "status": "PASS",
        "severity": "High",
        "finding": (
            "Insecure Application "
            "Credential Storage"
        ),
        "resource": arn,
        "impact": (
            "Application credentials are stored outside "
            "the application configuration and the "
            "expected AWS Secrets Manager secret is "
            "available for runtime retrieval."
        ),
        "remediation": (
            "Continue storing sensitive application "
            "credentials in AWS Secrets Manager and "
            "retrieve them at runtime."
        ),
        "evidence": (
            f"AWS Secrets Manager secret {SECRET_NAME} "
            "exists, is active, and no hard-coded "
            "credential patterns were detected in "
            f"{CREDENTIAL_FILE}."
        ),
    }


# ============================================================
# Run Secrets Checks
# ============================================================

def run_secrets_checks():

    return [
        check_sec_01()
    ]


# ============================================================
# Standalone Execution
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("SECRETS MANAGER SECURITY CHECKS")
    print("=" * 60)

    results = run_secrets_checks()

    for result in results:

        print()
        print(f"Check    : {result['id']}")
        print(f"Status   : {result['status']}")
        print(f"Severity : {result['severity']}")
        print(f"Finding  : {result['finding']}")
        print(f"Resource : {result['resource']}")
        print(f"Evidence : {result['evidence']}")

    print()
    print("=" * 60)
    print("Secrets Manager security checks complete")
    print("=" * 60)
