import boto3


ROLE_NAME = "AI-Security-Lab-Vulnerable-Role"


def get_attached_policy_documents():
    iam = boto3.client("iam")

    response = iam.list_attached_role_policies(
        RoleName=ROLE_NAME
    )

    documents = []

    for policy in response.get("AttachedPolicies", []):
        policy_arn = policy["PolicyArn"]

        policy_info = iam.get_policy(
            PolicyArn=policy_arn
        )

        version_id = policy_info["Policy"]["DefaultVersionId"]

        version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )

        document = version["PolicyVersion"]["Document"]

        documents.append(document)

    return documents


def check_iam_01():
    """
    IAM-01:
    Detect unrestricted application role permissions.

    Vulnerability:
        Action = *
        Resource = *
    """

    documents = get_attached_policy_documents()

    for document in documents:
        statements = document.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            actions = statement.get("Action")
            resources = statement.get("Resource")

            if (
                statement.get("Effect") == "Allow"
                and actions == "*"
                and resources == "*"
            ):
                return {
                    "id": "IAM-01",
                    "status": "FAIL",
                    "severity": "High",
                    "finding": "Excessive Application Role Permissions",
                    "resource": ROLE_NAME,
                    "impact": (
                        "The application role can potentially perform "
                        "unrestricted AWS actions against unrestricted "
                        "resources, increasing the blast radius of a "
                        "compromise."
                    ),
                    "remediation": (
                        "Apply least-privilege IAM permissions and allow "
                        "only the AWS actions and resources required by "
                        "the application."
                    ),
                    "evidence": (
                        f"Role {ROLE_NAME} contains an Allow statement "
                        "with Action=* and Resource=*."
                    )
                }

    return {
        "id": "IAM-01",
        "status": "PASS",
        "severity": "High",
        "finding": "Excessive Application Role Permissions",
        "resource": ROLE_NAME,
        "impact": (
            "The application role is protected from unrestricted AWS "
            "permissions."
        ),
        "remediation": (
            "Continue enforcing least-privilege IAM permissions."
        ),
        "evidence": (
            "No unrestricted Action/Resource combination found "
            "in attached policies."
        )
    }


def check_iam_02():
    """
    IAM-02:
    Detect unrestricted or potentially dangerous IAM permissions.
    """

    documents = get_attached_policy_documents()

    for document in documents:
        statements = document.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:

            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action")

            # Completely unrestricted permissions
            if actions == "*":
                return {
                    "id": "IAM-02",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": "IAM Privilege Escalation Permissions",
                    "resource": ROLE_NAME,
                    "impact": (
                        "Unrestricted permissions could allow a compromised "
                        "application identity to modify IAM resources or "
                        "perform privileged AWS operations."
                    ),
                    "remediation": (
                        "Remove unrestricted IAM permissions and grant only "
                        "the minimum actions required by the application."
                    ),
                    "evidence": (
                        f"Role {ROLE_NAME} contains an Allow statement "
                        "with unrestricted Action=*."
                    )
                }

            # IAM administrative permissions
            if isinstance(actions, list):

                dangerous_iam_actions = [
                    "iam:*",
                    "iam:PassRole",
                    "iam:CreateRole",
                    "iam:AttachRolePolicy",
                    "iam:PutRolePolicy",
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion"
                ]

                for action in actions:
                    if action.lower() in dangerous_iam_actions:
                        return {
                            "id": "IAM-02",
                            "status": "FAIL",
                            "severity": "Critical",
                            "finding": "IAM Privilege Escalation Permissions",
                            "resource": ROLE_NAME,
                            "impact": (
                                "The application role has IAM permissions "
                                "that could potentially be abused to "
                                "modify identities or escalate privileges."
                            ),
                            "remediation": (
                                "Remove unnecessary IAM administrative "
                                "permissions and restrict the role to "
                                "required application actions."
                            ),
                            "evidence": (
                                f"Role {ROLE_NAME} contains potentially "
                                f"dangerous IAM permission: {action}."
                            )
                        }

    return {
        "id": "IAM-02",
        "status": "PASS",
        "severity": "Critical",
        "finding": "IAM Privilege Escalation Permissions",
        "resource": ROLE_NAME,
        "impact": (
            "The application role does not contain unrestricted or "
            "detected dangerous IAM permissions."
        ),
        "remediation": (
            "Continue enforcing least-privilege IAM permissions."
        ),
        "evidence": (
            "No unrestricted IAM permissions detected in attached policies."
        )
    }


def check_iam_03():
    """
    IAM-03:
    Detect overly permissive role trust relationships.

    Vulnerability:
        Principal = *
    """

    iam = boto3.client("iam")

    role = iam.get_role(
        RoleName=ROLE_NAME
    )

    policy = role["Role"]["AssumeRolePolicyDocument"]

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        principal = statement.get("Principal")

        if principal == "*" or principal == {"AWS": "*"}:
            return {
                "id": "IAM-03",
                "status": "FAIL",
                "severity": "Critical",
                "finding": "Overly Permissive Role Trust Relationship",
                "resource": ROLE_NAME,
                "impact": (
                    "An unrestricted trust relationship could allow "
                    "unauthorized principals to assume the application "
                    "role."
                ),
                "remediation": (
                    "Restrict the role trust policy to only the specific "
                    "AWS service or principal that legitimately requires "
                    "permission to assume the role."
                ),
                "evidence": (
                    f"Role {ROLE_NAME} has a trust policy allowing "
                    "Principal AWS=*."
                )
            }

        if isinstance(principal, dict):

            aws_principal = principal.get("AWS")

            if aws_principal == "*":
                return {
                    "id": "IAM-03",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": "Overly Permissive Role Trust Relationship",
                    "resource": ROLE_NAME,
                    "impact": (
                        "An unrestricted trust relationship could allow "
                        "unauthorized principals to assume the application "
                        "role."
                    ),
                    "remediation": (
                        "Restrict the role trust policy to only the "
                        "specific AWS service or principal that requires "
                        "permission to assume the role."
                    ),
                    "evidence": (
                        f"Role {ROLE_NAME} has Principal AWS=*."
                    )
                }

    return {
        "id": "IAM-03",
        "status": "PASS",
        "severity": "Critical",
        "finding": "Overly Permissive Role Trust Relationship",
        "resource": ROLE_NAME,
        "impact": (
            "The application role can only be assumed by its intended "
            "trusted principal."
        ),
        "remediation": (
            "Continue restricting the trust relationship to required "
            "principals only."
        ),
        "evidence": (
            "Trust relationship is restricted."
        )
    }


def run_iam_checks():
    return [
        check_iam_01(),
        check_iam_02(),
        check_iam_03()
    ]
