import boto3
import json
import os
import sys
from urllib.parse import unquote


# ============================================================
# Make project root available when running directly
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


from scanner.resource_discovery import (
    discover_ai_role,
    discover_application_bucket,
)


# ============================================================
# Configuration
# ============================================================

REQUIRED_AI_OBJECT = "application-data.txt"

AI_CONFIG_PATH = os.path.join(
    PROJECT_ROOT,
    "insecure-app-config",
    "ai-config.json"
)


# ============================================================
# AWS Client
# ============================================================

def get_iam_client():
    return boto3.DEFAULT_SESSION.client("iam")


# ============================================================
# Helper: Get Attached Policy Statements
# ============================================================

def get_attached_policy_statements(iam, role_name):
    """
    Retrieve all statements from customer-managed policies
    attached to the specified IAM role.

    Returns:
        List of tuples:
        (policy_name, policy_arn, statement)
    """

    results = []

    response = iam.list_attached_role_policies(
        RoleName=role_name
    )

    attached_policies = response.get(
        "AttachedPolicies",
        []
    )

    for policy in attached_policies:

        policy_name = policy["PolicyName"]
        policy_arn = policy["PolicyArn"]

        try:

            policy_info = iam.get_policy(
                PolicyArn=policy_arn
            )

            version_id = (
                policy_info["Policy"]["DefaultVersionId"]
            )

            version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )

            document = (
                version["PolicyVersion"]["Document"]
            )

            # IAM policy documents may be URL encoded.
            if isinstance(document, str):
                document = unquote(document)
                document = json.loads(document)

            statements = document.get(
                "Statement",
                []
            )

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:

                results.append(
                    (
                        policy_name,
                        policy_arn,
                        statement
                    )
                )

        except Exception as e:

            print(
                f"Warning: unable to inspect "
                f"{policy_name}: {e}"
            )

    return results


# ============================================================
# AI-01
# Excessive IAM Permissions
# ============================================================

def check_ai_01():
    """
    AI-01:

    Detect excessive AWS permissions assigned to the
    generative-AI application workload role.

    The check evaluates the policies ACTUALLY ATTACHED
    to the discovered AI role.

    Vulnerability:

        Effect   = Allow
        Action   = *
        Resource = *

    """

    iam = get_iam_client()

    # --------------------------------------------------------
    # Discover AI role
    # --------------------------------------------------------

    ai_role_name = discover_ai_role()

    if not ai_role_name:

        return {
            "id": "AI-01",
            "status": "ERROR",
            "severity": "Critical",
            "finding": "AI Workload Role Not Found",
            "resource": "Project-tagged IAM role",
            "impact": (
                "The scanner could not identify the IAM "
                "role used by the AI application."
            ),
            "remediation": (
                "Ensure the AI workload IAM role has "
                "Project=AWS-AI-Security-Hardening-Lab "
                "and Component=AI-Application tags."
            ),
            "evidence": (
                "No project-tagged AI workload IAM role "
                "was discovered."
            ),
        }

    # --------------------------------------------------------
    # Inspect attached policies
    # --------------------------------------------------------

    try:

        policy_statements = get_attached_policy_statements(
            iam,
            ai_role_name
        )

    except Exception as e:

        return {
            "id": "AI-01",
            "status": "ERROR",
            "severity": "Critical",
            "finding": "Unable to Inspect AI Workload Policies",
            "resource": ai_role_name,
            "impact": (
                "The scanner could not inspect the policies "
                "attached to the AI workload role."
            ),
            "remediation": (
                "Verify IAM permissions for inspecting "
                "attached role policies."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Detect wildcard permissions
    # --------------------------------------------------------

    for policy_name, policy_arn, statement in policy_statements:

        effect = statement.get("Effect")

        actions = statement.get(
            "Action",
            []
        )

        resources = statement.get(
            "Resource",
            []
        )

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        if (
            effect == "Allow"
            and "*" in actions
            and "*" in resources
        ):

            return {
                "id": "AI-01",
                "status": "FAIL",
                "severity": "Critical",
                "finding": (
                    "Excessive Permissions for "
                    "Generative-AI Workload"
                ),
                "resource": ai_role_name,
                "impact": (
                    "A compromised AI application could "
                    "potentially perform arbitrary AWS "
                    "API actions."
                ),
                "remediation": (
                    "Replace wildcard permissions with "
                    "only the AWS actions and resources "
                    "required by the AI application."
                ),
                "evidence": (
                    f"Attached policy {policy_name} "
                    f"contains Effect=Allow, "
                    f"Action=* and Resource=*."
                ),
            }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "AI-01",
        "status": "PASS",
        "severity": "Critical",
        "finding": (
            "Excessive Permissions for "
            "Generative-AI Workload"
        ),
        "resource": ai_role_name,
        "impact": (
            "The AI workload is protected against "
            "unrestricted AWS permissions."
        ),
        "remediation": (
            "Continue enforcing least-privilege "
            "IAM permissions."
        ),
        "evidence": (
            "No attached AI workload policy contains "
            "an unrestricted Allow Action=* "
            "and Resource=* combination."
        ),
    }


# ============================================================
# AI-02
# Excessive S3 Data Access
# ============================================================

def check_ai_02():
    """
    AI-02:

    Detect excessive S3 data access by the AI workload.

    The check evaluates policies ACTUALLY ATTACHED
    to the discovered AI role.

    Broad access detected when:

        s3:GetObject  -> bucket/*
        OR
        s3:ListBucket -> bucket
    """

    iam = get_iam_client()

    # --------------------------------------------------------
    # Discover resources
    # --------------------------------------------------------

    ai_role_name = discover_ai_role()

    application_bucket = discover_application_bucket()

    # --------------------------------------------------------
    # Validate AI role
    # --------------------------------------------------------

    if not ai_role_name:

        return {
            "id": "AI-02",
            "status": "ERROR",
            "severity": "High",
            "finding": "AI Workload Role Not Found",
            "resource": "Project-tagged IAM role",
            "impact": (
                "The scanner could not identify the IAM "
                "role used by the AI application."
            ),
            "remediation": (
                "Ensure the AI workload IAM role has "
                "the required project tags."
            ),
            "evidence": (
                "No project-tagged AI workload role "
                "was discovered."
            ),
        }

    # --------------------------------------------------------
    # Validate application bucket
    # --------------------------------------------------------

    if not application_bucket:

        return {
            "id": "AI-02",
            "status": "ERROR",
            "severity": "High",
            "finding": "AI Application S3 Bucket Not Found",
            "resource": "Project-tagged S3 bucket",
            "impact": (
                "The scanner could not identify the S3 "
                "bucket containing the AI application's data."
            ),
            "remediation": (
                "Ensure the application S3 bucket has "
                "the required Project and Component tags."
            ),
            "evidence": (
                "No project-tagged AI application "
                "data bucket was discovered."
            ),
        }

    # --------------------------------------------------------
    # Construct ARNs
    # --------------------------------------------------------

    bucket_arn = (
        f"arn:aws:s3:::{application_bucket}"
    )

    object_arn = (
        f"{bucket_arn}/{REQUIRED_AI_OBJECT}"
    )

    all_objects_arn = (
        f"{bucket_arn}/*"
    )

    # --------------------------------------------------------
    # Inspect attached policies
    # --------------------------------------------------------

    try:

        policy_statements = get_attached_policy_statements(
            iam,
            ai_role_name
        )

    except Exception as e:

        return {
            "id": "AI-02",
            "status": "ERROR",
            "severity": "High",
            "finding": (
                "Unable to Inspect AI Workload Policies"
            ),
            "resource": ai_role_name,
            "impact": (
                "The scanner could not inspect the "
                "AI workload's IAM policies."
            ),
            "remediation": (
                "Verify IAM permissions for inspecting "
                "attached role policies."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Analyze every attached policy
    # --------------------------------------------------------

    for policy_name, policy_arn, statement in policy_statements:

        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get(
            "Action",
            []
        )

        resources = statement.get(
            "Resource",
            []
        )

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        # ----------------------------------------------------
        # Broad GetObject access
        # ----------------------------------------------------

        broad_data_access = (
            (
                "s3:GetObject" in actions
                or "s3:*" in actions
                or "*" in actions
            )
            and all_objects_arn in resources
        )

        # ----------------------------------------------------
        # Broad ListBucket access
        # ----------------------------------------------------

        broad_bucket_access = (
            (
                "s3:ListBucket" in actions
                or "s3:*" in actions
                or "*" in actions
            )
            and bucket_arn in resources
        )

        # ----------------------------------------------------
        # Vulnerability found
        # ----------------------------------------------------

        if broad_data_access or broad_bucket_access:

            return {
                "id": "AI-02",
                "status": "FAIL",
                "severity": "High",
                "finding": (
                    "Excessive Data Access by "
                    "Generative-AI Workload"
                ),
                "resource": application_bucket,
                "impact": (
                    "The AI workload can access more "
                    "application data than required, "
                    "increasing the risk of sensitive-data "
                    "exposure."
                ),
                "remediation": (
                    f"Restrict the AI workload to the "
                    f"required object: {object_arn}"
                ),
                "evidence": (
                    f"Attached policy {policy_name} "
                    f"grants broad S3 access to "
                    f"{application_bucket}."
                ),
            }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "AI-02",
        "status": "PASS",
        "severity": "High",
        "finding": (
            "Excessive Data Access by "
            "Generative-AI Workload"
        ),
        "resource": application_bucket,
        "impact": (
            "The AI workload is restricted to the "
            "minimum required application data."
        ),
        "remediation": (
            f"Maintain least-privilege access to "
            f"{object_arn}."
        ),
        "evidence": (
            "No attached AI workload policy grants "
            "broad access to the application S3 bucket."
        ),
    }


# ============================================================
# AI-03
# AI Input/Output Security Controls
# ============================================================

def check_ai_03():
    """
    AI-03:

    Validate application-level generative-AI
    input/output security controls.

    These controls are modeled locally rather than
    claiming that an actual Amazon Bedrock Guardrail
    resource is deployed.
    """

    # --------------------------------------------------------
    # Check configuration file
    # --------------------------------------------------------

    if not os.path.exists(AI_CONFIG_PATH):

        return {
            "id": "AI-03",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Missing Generative-AI "
                "Input/Output Security Controls"
            ),
            "resource": AI_CONFIG_PATH,
            "impact": (
                "The AI application has no verified "
                "configuration for input and output "
                "security controls."
            ),
            "remediation": (
                "Enable input validation, prompt-injection "
                "detection, output validation, "
                "sensitive-data filtering, and "
                "guardrail controls."
            ),
            "evidence": (
                "AI security configuration file not found."
            ),
        }

    # --------------------------------------------------------
    # Load configuration
    # --------------------------------------------------------

    try:

        with open(
            AI_CONFIG_PATH,
            "r"
        ) as file:

            config = json.load(file)

    except Exception as e:

        return {
            "id": "AI-03",
            "status": "ERROR",
            "severity": "High",
            "finding": (
                "Invalid Generative-AI "
                "Security Configuration"
            ),
            "resource": AI_CONFIG_PATH,
            "impact": (
                "The AI application's security "
                "configuration could not be parsed."
            ),
            "remediation": (
                "Ensure the AI configuration file "
                "contains valid JSON."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Required controls
    # --------------------------------------------------------

    required_controls = [
        "input_validation",
        "prompt_injection_detection",
        "output_validation",
        "sensitive_data_filtering",
        "guardrails_enabled",
    ]

    # --------------------------------------------------------
    # Find disabled controls
    # --------------------------------------------------------

    disabled_controls = [
        control
        for control in required_controls
        if config.get(control) is not True
    ]

    # --------------------------------------------------------
    # Vulnerability found
    # --------------------------------------------------------

    if disabled_controls:

        return {
            "id": "AI-03",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Missing Generative-AI "
                "Input/Output Security Controls"
            ),
            "resource": AI_CONFIG_PATH,
            "impact": (
                "The generative-AI application may be "
                "exposed to unsafe prompts, prompt "
                "injection, or sensitive-data leakage."
            ),
            "remediation": (
                "Enable all required AI input/output "
                "security controls."
            ),
            "evidence": (
                "Disabled AI security controls: "
                + ", ".join(disabled_controls)
            ),
        }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "AI-03",
        "status": "PASS",
        "severity": "High",
        "finding": (
            "Missing Generative-AI "
            "Input/Output Security Controls"
        ),
        "resource": AI_CONFIG_PATH,
        "impact": (
            "The generative-AI application has "
            "configured input/output security "
            "protections."
        ),
        "remediation": (
            "Maintain input validation, "
            "prompt-injection detection, "
            "output validation, sensitive-data "
            "filtering, and guardrail controls."
        ),
        "evidence": (
            "All required generative-AI "
            "input/output security controls are enabled."
        ),
    }


# ============================================================
# Run All AI Checks
# ============================================================

def run_ai_checks():
    """
    Execute all AI security checks.
    """

    return [
        check_ai_01(),
        check_ai_02(),
        check_ai_03(),
    ]


# ============================================================
# Standalone Execution
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("AI SECURITY CHECKS")
    print("=" * 60)

    results = run_ai_checks()

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
    print("AI security checks complete")
    print("=" * 60)
