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


from scanner.resource_discovery import discover_ai_role


# ============================================================
# AWS Client
# ============================================================

def get_iam_client():
    return boto3.Session().client("iam")


# ============================================================
# Policy Document Helper
# ============================================================

def normalize_policy_document(document):
    """
    Normalize an IAM policy document returned by AWS.
    """

    if isinstance(document, str):
        document = unquote(document)
        document = json.loads(document)

    return document


# ============================================================
# Get Managed Policy Documents
# ============================================================

def get_attached_policy_documents(iam, role_name):
    """
    Retrieve all managed policies attached to the role.

    Returns:
        List of tuples:
        (policy_name, policy_arn, document)
    """

    documents = []

    paginator = iam.get_paginator(
        "list_attached_role_policies"
    )

    for page in paginator.paginate(
        RoleName=role_name
    ):

        for policy in page.get(
            "AttachedPolicies",
            []
        ):

            policy_name = policy["PolicyName"]
            policy_arn = policy["PolicyArn"]

            try:

                policy_info = iam.get_policy(
                    PolicyArn=policy_arn
                )

                version_id = (
                    policy_info["Policy"]
                    ["DefaultVersionId"]
                )

                version = iam.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )

                document = normalize_policy_document(
                    version["PolicyVersion"]["Document"]
                )

                documents.append(
                    (
                        policy_name,
                        policy_arn,
                        document
                    )
                )

            except Exception as e:

                print(
                    f"Warning: unable to inspect "
                    f"{policy_name}: {e}"
                )

    return documents


# ============================================================
# IAM-01
# Excessive Application Role Permissions
# ============================================================

def check_iam_01():
    """
    IAM-01:

    Detect unrestricted permissions assigned to the
    discovered AI application role.

    Vulnerability:

        Effect   = Allow
        Action   = *
        Resource = *
    """

    iam = get_iam_client()

    role_name = discover_ai_role()

    # --------------------------------------------------------
    # Role discovery
    # --------------------------------------------------------

    if not role_name:

        return {
            "id": "IAM-01",
            "status": "ERROR",
            "severity": "High",
            "finding": "Excessive Application Role Permissions",
            "resource": "Project-tagged AI IAM role",
            "impact": (
                "The scanner could not identify the IAM role "
                "used by the AI application."
            ),
            "remediation": (
                "Ensure the AI workload role has the required "
                "Project and Component tags."
            ),
            "evidence": (
                "No project-tagged AI application role "
                "was discovered."
            ),
        }

    # --------------------------------------------------------
    # Retrieve policies
    # --------------------------------------------------------

    try:

        policies = get_attached_policy_documents(
            iam,
            role_name
        )

    except Exception as e:

        return {
            "id": "IAM-01",
            "status": "ERROR",
            "severity": "High",
            "finding": "Excessive Application Role Permissions",
            "resource": role_name,
            "impact": (
                "The scanner could not inspect the "
                "policies attached to the AI role."
            ),
            "remediation": (
                "Verify IAM permissions and inspect the "
                "attached role policies."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Analyze every policy
    # --------------------------------------------------------

    for policy_name, policy_arn, document in policies:

        statements = document.get(
            "Statement",
            []
        )

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:

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

            if (
                "*" in actions
                and "*" in resources
            ):

                return {
                    "id": "IAM-01",
                    "status": "FAIL",
                    "severity": "High",
                    "finding": (
                        "Excessive Application "
                        "Role Permissions"
                    ),
                    "resource": role_name,
                    "impact": (
                        "The application role can potentially "
                        "perform unrestricted AWS actions against "
                        "unrestricted resources, increasing the "
                        "blast radius of a compromise."
                    ),
                    "remediation": (
                        "Apply least-privilege IAM permissions "
                        "and allow only the AWS actions and "
                        "resources required by the application."
                    ),
                    "evidence": (
                        f"Attached policy {policy_name} "
                        "contains an Allow statement with "
                        "Action=* and Resource=*."
                    ),
                }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "IAM-01",
        "status": "PASS",
        "severity": "High",
        "finding": (
            "Excessive Application "
            "Role Permissions"
        ),
        "resource": role_name,
        "impact": (
            "The application role is protected from "
            "unrestricted AWS permissions."
        ),
        "remediation": (
            "Continue enforcing least-privilege "
            "IAM permissions."
        ),
        "evidence": (
            "No unrestricted Action=* and "
            "Resource=* combination was found "
            "in attached policies."
        ),
    }


# ============================================================
# IAM-02
# IAM Privilege Escalation Permissions
# ============================================================

def check_iam_02():
    """
    IAM-02:

    Detect unrestricted or potentially dangerous IAM
    permissions.
    """

    iam = get_iam_client()

    role_name = discover_ai_role()

    # --------------------------------------------------------
    # Role discovery
    # --------------------------------------------------------

    if not role_name:

        return {
            "id": "IAM-02",
            "status": "ERROR",
            "severity": "Critical",
            "finding": "IAM Privilege Escalation Permissions",
            "resource": "Project-tagged AI IAM role",
            "impact": (
                "The scanner could not identify the "
                "AI application IAM role."
            ),
            "remediation": (
                "Ensure the AI workload role has the "
                "required project tags."
            ),
            "evidence": (
                "No project-tagged AI IAM role was discovered."
            ),
        }

    try:

        policies = get_attached_policy_documents(
            iam,
            role_name
        )

    except Exception as e:

        return {
            "id": "IAM-02",
            "status": "ERROR",
            "severity": "Critical",
            "finding": "IAM Privilege Escalation Permissions",
            "resource": role_name,
            "impact": (
                "The scanner could not inspect the "
                "AI application's IAM policies."
            ),
            "remediation": (
                "Verify IAM permissions and inspect "
                "attached policies."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Dangerous IAM actions
    # --------------------------------------------------------

    dangerous_iam_actions = [
        "iam:*",
        "iam:PassRole",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:PutUserPolicy",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:CreateAccessKey",
        "iam:UpdateAssumeRolePolicy",
    ]

    # --------------------------------------------------------
    # Analyze every policy
    # --------------------------------------------------------

    for policy_name, policy_arn, document in policies:

        statements = document.get(
            "Statement",
            []
        )

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:

            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get(
                "Action",
                []
            )

            if isinstance(actions, str):
                actions = [actions]

            normalized_actions = [
                action.lower()
                for action in actions
            ]

            # Completely unrestricted permissions
            if "*" in actions:

                return {
                    "id": "IAM-02",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": (
                        "IAM Privilege Escalation Permissions"
                    ),
                    "resource": role_name,
                    "impact": (
                        "Unrestricted permissions could allow "
                        "a compromised application identity to "
                        "modify IAM resources or perform "
                        "privileged AWS operations."
                    ),
                    "remediation": (
                        "Remove unrestricted IAM permissions "
                        "and grant only the minimum actions "
                        "required by the application."
                    ),
                    "evidence": (
                        f"Attached policy {policy_name} "
                        "contains an Allow statement with "
                        "unrestricted Action=*."
                    ),
                }

            # Specific dangerous IAM permissions
            for action in normalized_actions:

                if action in dangerous_iam_actions:

                    return {
                        "id": "IAM-02",
                        "status": "FAIL",
                        "severity": "Critical",
                        "finding": (
                            "IAM Privilege Escalation Permissions"
                        ),
                        "resource": role_name,
                        "impact": (
                            "The application role has IAM "
                            "permissions that could potentially "
                            "be abused to modify identities "
                            "or escalate privileges."
                        ),
                        "remediation": (
                            "Remove unnecessary IAM "
                            "administrative permissions and "
                            "restrict the role to required "
                            "application actions."
                        ),
                        "evidence": (
                            f"Attached policy {policy_name} "
                            f"contains potentially dangerous "
                            f"IAM permission: {action}."
                        ),
                    }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "IAM-02",
        "status": "PASS",
        "severity": "Critical",
        "finding": (
            "IAM Privilege Escalation Permissions"
        ),
        "resource": role_name,
        "impact": (
            "The application role does not contain "
            "unrestricted or detected dangerous IAM "
            "permissions."
        ),
        "remediation": (
            "Continue enforcing least-privilege "
            "IAM permissions."
        ),
        "evidence": (
            "No unrestricted or detected dangerous "
            "IAM permissions were found."
        ),
    }


# ============================================================
# IAM-03
# Overly Permissive Role Trust Relationship
# ============================================================

def check_iam_03():
    """
    IAM-03:

    Detect overly permissive role trust relationships.

    Vulnerability:

        Principal = *
    """

    iam = get_iam_client()

    role_name = discover_ai_role()

    # --------------------------------------------------------
    # Role discovery
    # --------------------------------------------------------

    if not role_name:

        return {
            "id": "IAM-03",
            "status": "ERROR",
            "severity": "Critical",
            "finding": (
                "Overly Permissive Role "
                "Trust Relationship"
            ),
            "resource": "Project-tagged AI IAM role",
            "impact": (
                "The scanner could not identify the "
                "AI application IAM role."
            ),
            "remediation": (
                "Ensure the AI workload role has the "
                "required project tags."
            ),
            "evidence": (
                "No project-tagged AI IAM role was discovered."
            ),
        }

    # --------------------------------------------------------
    # Retrieve trust policy
    # --------------------------------------------------------

    try:

        role = iam.get_role(
            RoleName=role_name
        )

        policy = (
            role["Role"]
            ["AssumeRolePolicyDocument"]
        )

    except Exception as e:

        return {
            "id": "IAM-03",
            "status": "ERROR",
            "severity": "Critical",
            "finding": (
                "Overly Permissive Role "
                "Trust Relationship"
            ),
            "resource": role_name,
            "impact": (
                "The scanner could not inspect "
                "the role trust policy."
            ),
            "remediation": (
                "Verify IAM permissions and inspect "
                "the role trust relationship."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Analyze trust policy
    # --------------------------------------------------------

    statements = policy.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get(
            "Principal"
        )

        # ----------------------------------------------------
        # Principal = *
        # ----------------------------------------------------

        if principal == "*":

            return {
                "id": "IAM-03",
                "status": "FAIL",
                "severity": "Critical",
                "finding": (
                    "Overly Permissive Role "
                    "Trust Relationship"
                ),
                "resource": role_name,
                "impact": (
                    "An unrestricted trust relationship could "
                    "allow unauthorized principals to assume "
                    "the application role."
                ),
                "remediation": (
                    "Restrict the role trust policy to only "
                    "the specific AWS service or principal "
                    "that legitimately requires permission "
                    "to assume the role."
                ),
                "evidence": (
                    f"Role {role_name} has a trust policy "
                    "allowing Principal=*."
                ),
            }

        # ----------------------------------------------------
        # Principal AWS = *
        # ----------------------------------------------------

        if isinstance(principal, dict):

            aws_principal = principal.get(
                "AWS"
            )

            if aws_principal == "*":

                return {
                    "id": "IAM-03",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": (
                        "Overly Permissive Role "
                        "Trust Relationship"
                    ),
                    "resource": role_name,
                    "impact": (
                        "An unrestricted trust relationship "
                        "could allow unauthorized principals "
                        "to assume the application role."
                    ),
                    "remediation": (
                        "Restrict the role trust policy to "
                        "only the specific AWS service or "
                        "principal that requires the role."
                    ),
                    "evidence": (
                        f"Role {role_name} has "
                        "Principal AWS=*."
                    ),
                }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "IAM-03",
        "status": "PASS",
        "severity": "Critical",
        "finding": (
            "Overly Permissive Role "
            "Trust Relationship"
        ),
        "resource": role_name,
        "impact": (
            "The application role can only be assumed "
            "by its intended trusted principal."
        ),
        "remediation": (
            "Continue restricting the trust relationship "
            "to required principals only."
        ),
        "evidence": (
            "Trust relationship is restricted."
        ),
    }


# ============================================================
# Run All IAM Checks
# ============================================================

def run_iam_checks():

    return [
        check_iam_01(),
        check_iam_02(),
        check_iam_03(),
    ]


# ============================================================
# Standalone Execution
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("IAM SECURITY CHECKS")
    print("=" * 60)

    results = run_iam_checks()

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
    print("IAM security checks complete")
    print("=" * 60)
