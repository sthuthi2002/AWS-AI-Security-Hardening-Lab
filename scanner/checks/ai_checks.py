import boto3
import json
import os


AI_ROLE_NAME = "AI-Security-Lab-AI-Workload-Role"
AI_POLICY_NAME = "AI-Security-Lab-AI-Workload-Vulnerable-Policy"
AI_DATA_POLICY_NAME = "AI-Security-Lab-AI-Data-Access-Vulnerable-Policy"

APPLICATION_BUCKET = "ai-security-lab-data-256148542278"
REQUIRED_AI_OBJECT = "application-data.txt"

AI_CONFIG_PATH = "insecure-app-config/ai-config.json"


def check_ai_01():
    """
    AI-01:
    Detect excessive AWS permissions assigned to the
    generative-AI application workload role.

    Security scenario:
    A compromised AI application should not be able
    to perform arbitrary AWS actions.
    """

    iam = boto3.client("iam")

    policies = iam.list_attached_role_policies(
        RoleName=AI_ROLE_NAME
    )["AttachedPolicies"]

    for policy in policies:

        if policy["PolicyName"] != AI_POLICY_NAME:
            continue

        policy_arn = policy["PolicyArn"]

        policy_info = iam.get_policy(
            PolicyArn=policy_arn
        )

        version_id = policy_info["Policy"]["DefaultVersionId"]

        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )

        statements = version["PolicyVersion"]["Document"]["Statement"]

        for statement in statements:

            if (
                statement.get("Effect") == "Allow"
                and statement.get("Action") == "*"
                and statement.get("Resource") == "*"
            ):
                return {
                    "id": "AI-01",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": "Excessive Permissions for Generative-AI Workload",
                    "resource": AI_ROLE_NAME,
                    "impact": (
                        "A compromised AI application could potentially "
                        "perform arbitrary AWS API actions."
                    ),
                    "remediation": (
                        "Replace wildcard permissions with only the AWS "
                        "actions and resources required by the AI application."
                    ),
                    "evidence": (
                        f"Generative-AI workload role {AI_ROLE_NAME} "
                        "contains Action=* and Resource=*."
                    )
                }

    return {
        "id": "AI-01",
        "status": "PASS",
        "severity": "Critical",
        "finding": "Excessive Permissions for Generative-AI Workload",
        "resource": AI_ROLE_NAME,
        "impact": (
            "The AI workload is protected against unrestricted AWS permissions."
        ),
        "remediation": (
            "Continue enforcing least-privilege IAM permissions."
        ),
        "evidence": (
            "No unrestricted Action/Resource combination found "
            "in the AI workload policies."
        )
    }


def check_ai_02():
    """
    AI-02:
    Detect excessive S3 data access by the AI workload.

    Security scenario:
    The generative-AI application only requires access
    to a specific application object, not the entire bucket.
    """

    iam = boto3.client("iam")

    policies = iam.list_attached_role_policies(
        RoleName=AI_ROLE_NAME
    )["AttachedPolicies"]

    bucket_arn = f"arn:aws:s3:::{APPLICATION_BUCKET}"
    object_arn = f"{bucket_arn}/{REQUIRED_AI_OBJECT}"
    all_objects_arn = f"{bucket_arn}/*"

    for policy in policies:

        if policy["PolicyName"] != AI_DATA_POLICY_NAME:
            continue

        policy_arn = policy["PolicyArn"]

        policy_info = iam.get_policy(
            PolicyArn=policy_arn
        )

        version_id = policy_info["Policy"]["DefaultVersionId"]

        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )

        statements = version["PolicyVersion"]["Document"]["Statement"]

        for statement in statements:

            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])

            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])

            if isinstance(resources, str):
                resources = [resources]

            broad_data_access = (
                "s3:GetObject" in actions
                and all_objects_arn in resources
            )

            broad_bucket_access = (
                "s3:ListBucket" in actions
                and bucket_arn in resources
            )

            if broad_data_access or broad_bucket_access:

                return {
                    "id": "AI-02",
                    "status": "FAIL",
                    "severity": "High",
                    "finding": "Excessive Data Access by Generative-AI Workload",
                    "resource": APPLICATION_BUCKET,
                    "impact": (
                        "The AI workload can access more application data "
                        "than required, increasing the risk of sensitive-data exposure."
                    ),
                    "remediation": (
                        f"Restrict the AI workload to the required object: "
                        f"{object_arn}"
                    ),
                    "evidence": (
                        f"AI workload has broad S3 access to "
                        f"{APPLICATION_BUCKET}."
                    )
                }

    return {
        "id": "AI-02",
        "status": "PASS",
        "severity": "High",
        "finding": "Excessive Data Access by Generative-AI Workload",
        "resource": APPLICATION_BUCKET,
        "impact": (
            "The AI workload is restricted to the minimum required application data."
        ),
        "remediation": (
            f"Maintain least-privilege access to {object_arn}."
        ),
        "evidence": (
            f"AI workload data access is restricted to the required "
            f"application resource."
        )
    }


def check_ai_03():
    """
    AI-03:
    Validate application-level generative-AI input/output security controls.

    These controls are modeled locally rather than claiming that
    an actual Amazon Bedrock Guardrail resource is deployed.
    """

    if not os.path.exists(AI_CONFIG_PATH):

        return {
            "id": "AI-03",
            "status": "FAIL",
            "severity": "High",
            "finding": "Missing Generative-AI Input/Output Security Controls",
            "resource": AI_CONFIG_PATH,
            "impact": (
                "The AI application has no verified configuration "
                "for input and output security controls."
            ),
            "remediation": (
                "Enable input validation, prompt-injection detection, "
                "output validation, sensitive-data filtering, and guardrail controls."
            ),
            "evidence": "AI security configuration file not found."
        }

    with open(AI_CONFIG_PATH, "r") as file:
        config = json.load(file)

    required_controls = [
        "input_validation",
        "prompt_injection_detection",
        "output_validation",
        "sensitive_data_filtering",
        "guardrails_enabled"
    ]

    disabled_controls = [
        control
        for control in required_controls
        if config.get(control) is not True
    ]

    if disabled_controls:

        return {
            "id": "AI-03",
            "status": "FAIL",
            "severity": "High",
            "finding": "Missing Generative-AI Input/Output Security Controls",
            "resource": AI_CONFIG_PATH,
            "impact": (
                "The generative-AI application may be exposed to "
                "unsafe prompts, prompt injection, or sensitive-data leakage."
            ),
            "remediation": (
                "Enable all required AI input/output security controls."
            ),
            "evidence": (
                "Disabled AI security controls: "
                + ", ".join(disabled_controls)
            )
        }

    return {
        "id": "AI-03",
        "status": "PASS",
        "severity": "High",
        "finding": "Missing Generative-AI Input/Output Security Controls",
        "resource": AI_CONFIG_PATH,
        "impact": (
            "The generative-AI application has configured input/output "
            "security protections."
        ),
        "remediation": (
            "Maintain input validation, prompt-injection detection, "
            "output validation, sensitive-data filtering, and guardrail controls."
        ),
        "evidence": (
            "All required generative-AI input/output security controls are enabled."
        )
    }


def run_ai_checks():
    return [
        check_ai_01(),
        check_ai_02(),
        check_ai_03()
    ]
