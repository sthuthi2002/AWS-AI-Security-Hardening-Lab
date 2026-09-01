import boto3
import json
import os


AI_ROLE_NAME = "AI-Security-Lab-AI-Workload-Role"
AI_POLICY_NAME = "AI-Security-Lab-AI-Workload-Vulnerable-Policy"
AI_DATA_POLICY_NAME = "AI-Security-Lab-AI-Data-Access-Vulnerable-Policy"

APPLICATION_BUCKET = "ai-security-lab-data-256148542278"
AI_CONFIG_PATH = "insecure-app-config/ai-config.json"


def check_ai_01():
    iam = boto3.client("iam")

    policies = iam.list_attached_role_policies(
        RoleName=AI_ROLE_NAME
    )["AttachedPolicies"]

    for policy in policies:
        if policy["PolicyName"] == AI_POLICY_NAME:
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
                        "finding": "Excessive Permissions for AI Workload",
                        "evidence": (
                            f"AI workload role {AI_ROLE_NAME} "
                            "has Action=* and Resource=*"
                        )
                    }

    return {
        "id": "AI-01",
        "status": "PASS",
        "severity": "Critical",
        "finding": "Excessive Permissions for AI Workload",
        "evidence": "AI workload permissions are restricted"
    }


def check_ai_02():
    iam = boto3.client("iam")

    policies = iam.list_attached_role_policies(
        RoleName=AI_ROLE_NAME
    )["AttachedPolicies"]

    for policy in policies:
        if policy["PolicyName"] == AI_DATA_POLICY_NAME:
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
                resources = statement.get("Resource", [])

                if isinstance(resources, str):
                    resources = [resources]

                bucket_arn = f"arn:aws:s3:::{APPLICATION_BUCKET}"
                object_arn = f"arn:aws:s3:::{APPLICATION_BUCKET}/*"

                if (
                    statement.get("Effect") == "Allow"
                    and (
                        bucket_arn in resources
                        or object_arn in resources
                    )
                ):
                    return {
                        "id": "AI-02",
                        "status": "FAIL",
                        "severity": "High",
                        "finding": "Excessive Data Access by AI Workload",
                        "evidence": (
                            f"AI workload has S3 access to "
                            f"{APPLICATION_BUCKET}"
                        )
                    }

    return {
        "id": "AI-02",
        "status": "PASS",
        "severity": "High",
        "finding": "Excessive Data Access by AI Workload",
        "evidence": "AI workload data access is restricted"
    }


def check_ai_03():
    if not os.path.exists(AI_CONFIG_PATH):
        return {
            "id": "AI-03",
            "status": "PASS",
            "severity": "High",
            "finding": "Missing AI Input/Output Security Controls",
            "evidence": "AI configuration file not found"
        }

    with open(AI_CONFIG_PATH, "r") as file:
        config = json.load(file)

    insecure_controls = [
        "input_validation",
        "prompt_injection_detection",
        "output_validation",
        "sensitive_data_filtering",
        "guardrails_enabled"
    ]

    disabled_controls = [
        control
        for control in insecure_controls
        if config.get(control) is False
    ]

    if disabled_controls:
        return {
            "id": "AI-03",
            "status": "FAIL",
            "severity": "High",
            "finding": "Missing AI Input/Output Security Controls",
            "evidence": (
                "Disabled AI security controls: "
                + ", ".join(disabled_controls)
            )
        }

    return {
        "id": "AI-03",
        "status": "PASS",
        "severity": "High",
        "finding": "Missing AI Input/Output Security Controls",
        "evidence": "AI security controls are enabled"
    }


def run_ai_checks():
    return [
        check_ai_01(),
        check_ai_02(),
        check_ai_03()
    ]
