from pathlib import Path


CREDENTIAL_FILE = Path("insecure-app-config/application.env")
SECURE_CONFIG_FILE = Path("remediation/application-secure.env")

SECRET_NAME = "AI-Security-Lab-Dummy-Credential"


def check_sec_01():
    """
    SEC-01:
    Detect insecure storage of application credentials.

    Baseline:
        Credentials are stored directly in application.env.

    Remediated:
        Application retrieves credentials from AWS Secrets Manager.
    """

    # ---------------------------------------------------------
    # Remediated secure configuration
    # ---------------------------------------------------------

    if SECURE_CONFIG_FILE.exists():

        secure_config = SECURE_CONFIG_FILE.read_text()

        required_settings = [
            "APP_PASSWORD_FROM_SECRETS_MANAGER=true",
            "AWS_CREDENTIALS_FROM_SECRETS_MANAGER=true",
            f"SECRET_NAME={SECRET_NAME}"
        ]

        if all(setting in secure_config for setting in required_settings):

            return {
                "id": "SEC-01",
                "status": "PASS",
                "severity": "High",
                "finding": "Insecure Application Credential Storage",
                "resource": SECRET_NAME,
                "impact": (
                    "Application credentials are no longer stored directly "
                    "in the application configuration. Using AWS Secrets "
                    "Manager reduces the risk of credential exposure."
                ),
                "remediation": (
                    "Store application credentials in AWS Secrets Manager "
                    "and retrieve them at runtime instead of hardcoding "
                    "credential values in application configuration files."
                ),
                "evidence": (
                    f"Application configuration uses AWS Secrets Manager "
                    f"secret {SECRET_NAME}."
                )
            }

    # ---------------------------------------------------------
    # Baseline vulnerable configuration
    # ---------------------------------------------------------

    if CREDENTIAL_FILE.exists():

        content = CREDENTIAL_FILE.read_text()

        sensitive_patterns = [
            "APP_PASSWORD=",
            "AWS_ACCESS_KEY_ID=",
            "AWS_SECRET_ACCESS_KEY="
        ]

        found = [
            pattern
            for pattern in sensitive_patterns
            if pattern in content
        ]

        if found:

            return {
                "id": "SEC-01",
                "status": "FAIL",
                "severity": "High",
                "finding": "Insecure Application Credential Storage",
                "resource": str(CREDENTIAL_FILE),
                "impact": (
                    "Hardcoded passwords and AWS credentials can be exposed "
                    "through source code, configuration files, backups, or "
                    "unauthorized access to the application environment."
                ),
                "remediation": (
                    "Move sensitive credentials into AWS Secrets Manager "
                    "and remove credential values from application "
                    "configuration files."
                ),
                "evidence": (
                    f"Sensitive credential material detected in "
                    f"{CREDENTIAL_FILE}: {', '.join(found)}"
                )
            }

    # ---------------------------------------------------------
    # No insecure configuration detected
    # ---------------------------------------------------------

    return {
        "id": "SEC-01",
        "status": "PASS",
        "severity": "High",
        "finding": "Insecure Application Credential Storage",
        "resource": SECRET_NAME,
        "impact": (
            "No insecure application credential storage was detected."
        ),
        "remediation": (
            "Continue storing sensitive application credentials in "
            "AWS Secrets Manager."
        ),
        "evidence": (
            "No sensitive credential patterns detected in the "
            "application configuration."
        )
    }


def run_secrets_checks():
    return [check_sec_01()]
