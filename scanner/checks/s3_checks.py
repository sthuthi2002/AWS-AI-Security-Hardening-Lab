import boto3
import json
import os
import sys


# ============================================================
# Make project root available when running directly
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


from scanner.resource_discovery import (
    discover_application_bucket,
)


# ============================================================
# AWS Client
# ============================================================

def get_s3_client():
    return boto3.DEFAULT_SESSION.client("s3")


# ============================================================
# Discover Application Bucket
# ============================================================

def get_application_bucket():
    """
    Discover the application S3 bucket using the project
    and component tags.

    Expected tags:

        Project   = AWS-AI-Security-Hardening-Lab
        Component = AI-Application-Data
    """

    return discover_application_bucket()


# ============================================================
# Get Bucket Policy
# ============================================================

def get_bucket_policy(bucket_name):
    """
    Retrieve the bucket policy.

    Returns:
        Policy dictionary
        None if no bucket policy exists
    """

    s3 = get_s3_client()

    try:

        response = s3.get_bucket_policy(
            Bucket=bucket_name
        )

        return json.loads(
            response["Policy"]
        )

    except s3.exceptions.NoSuchBucket:

        return None

    except s3.exceptions.ClientError as e:

        error_code = e.response.get(
            "Error",
            {}
        ).get("Code")

        if error_code in [
            "NoSuchBucketPolicy",
            "AccessDenied"
        ]:

            return None

        raise


# ============================================================
# S3-01
# Public Application Data
# ============================================================

def check_s3_01():
    """
    S3-01:

    Detect public access to application data.
    """

    bucket_name = get_application_bucket()

    # --------------------------------------------------------
    # Bucket discovery failure
    # --------------------------------------------------------

    if not bucket_name:

        return {
            "id": "S3-01",
            "status": "ERROR",
            "severity": "Critical",
            "finding": "Public Application Data",
            "resource": "Application S3 bucket",
            "impact": (
                "The scanner could not identify the "
                "project application bucket."
            ),
            "remediation": (
                "Ensure the application bucket has the tags "
                "Project=AWS-AI-Security-Hardening-Lab and "
                "Component=AI-Application-Data."
            ),
            "evidence": (
                "No project-tagged application bucket "
                "was discovered."
            ),
        }

    # --------------------------------------------------------
    # Get bucket policy
    # --------------------------------------------------------

    policy = get_bucket_policy(bucket_name)

    if policy is None:

        return {
            "id": "S3-01",
            "status": "PASS",
            "severity": "Critical",
            "finding": "Public Application Data",
            "resource": bucket_name,
            "impact": (
                "No bucket policy was found that grants "
                "public access to application data."
            ),
            "remediation": (
                "Maintain private bucket access and ensure "
                "that no public Allow policy grants access "
                "to application objects."
            ),
            "evidence": (
                f"No bucket policy allowing public object "
                f"access was detected for {bucket_name}."
            ),
        }

    # --------------------------------------------------------
    # Analyze policy statements
    # --------------------------------------------------------

    statements = policy.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        effect = statement.get("Effect")

        principal = statement.get(
            "Principal"
        )

        action = statement.get(
            "Action"
        )

        # Only public Allow statements are dangerous.
        if effect != "Allow":
            continue

        # ----------------------------------------------------
        # Determine whether principal is public
        # ----------------------------------------------------

        public_principal = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and principal.get("AWS") == "*"
            )
        )

        if not public_principal:
            continue

        # ----------------------------------------------------
        # Normalize actions
        # ----------------------------------------------------

        actions = (
            action
            if isinstance(action, list)
            else [action]
        )

        # ----------------------------------------------------
        # Detect public object access
        # ----------------------------------------------------

        for current_action in actions:

            if current_action in [
                "s3:GetObject",
                "s3:*",
                "*",
            ]:

                return {
                    "id": "S3-01",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": "Public Application Data",
                    "resource": bucket_name,
                    "impact": (
                        "Unauthenticated or publicly accessible "
                        "users could retrieve application data "
                        "from the S3 bucket."
                    ),
                    "remediation": (
                        "Remove public Allow permissions and "
                        "restrict bucket access to authorized "
                        "AWS principals."
                    ),
                    "evidence": (
                        f"Bucket {bucket_name} contains an "
                        "Allow statement that grants public "
                        "object access."
                    ),
                }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "S3-01",
        "status": "PASS",
        "severity": "Critical",
        "finding": "Public Application Data",
        "resource": bucket_name,
        "impact": (
            "Application data is not publicly accessible "
            "through the bucket policy."
        ),
        "remediation": (
            "Continue restricting bucket access to "
            "authorized principals."
        ),
        "evidence": (
            f"No public Allow statement detected "
            f"for {bucket_name}."
        ),
    }


# ============================================================
# S3-02
# S3 Public Access Block
# ============================================================

def check_s3_02():
    """
    S3-02:

    Detect missing or incomplete S3 Public Access Block
    protection.
    """

    bucket_name = get_application_bucket()

    # --------------------------------------------------------
    # Bucket discovery failure
    # --------------------------------------------------------

    if not bucket_name:

        return {
            "id": "S3-02",
            "status": "ERROR",
            "severity": "High",
            "finding": "Public Access Protection Disabled",
            "resource": "Application S3 bucket",
            "impact": (
                "The scanner could not identify the "
                "project application bucket."
            ),
            "remediation": (
                "Ensure the application bucket has the "
                "required project tags."
            ),
            "evidence": (
                "No project-tagged application bucket "
                "was discovered."
            ),
        }

    s3 = get_s3_client()

    # --------------------------------------------------------
    # Retrieve Public Access Block
    # --------------------------------------------------------

    try:

        config = s3.get_public_access_block(
            Bucket=bucket_name
        )["PublicAccessBlockConfiguration"]

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:

        return {
            "id": "S3-02",
            "status": "FAIL",
            "severity": "High",
            "finding": "Public Access Protection Disabled",
            "resource": bucket_name,
            "impact": (
                "The bucket does not have S3 Public Access "
                "Block protection configured, increasing "
                "the risk of accidental public exposure."
            ),
            "remediation": (
                "Enable all four S3 Public Access Block "
                "controls: BlockPublicAcls, IgnorePublicAcls, "
                "BlockPublicPolicy, and RestrictPublicBuckets."
            ),
            "evidence": (
                f"No Public Access Block configuration "
                f"was found for {bucket_name}."
            ),
        }

    except s3.exceptions.ClientError as e:

        return {
            "id": "S3-02",
            "status": "ERROR",
            "severity": "High",
            "finding": "Unable to Inspect Public Access Block",
            "resource": bucket_name,
            "impact": (
                "The scanner could not determine whether "
                "S3 Public Access Block protection is enabled."
            ),
            "remediation": (
                "Verify S3 permissions and inspect the "
                "bucket Public Access Block configuration."
            ),
            "evidence": str(e),
        }

    # --------------------------------------------------------
    # Validate all four controls
    # --------------------------------------------------------

    controls = [
        config.get("BlockPublicAcls", False),
        config.get("IgnorePublicAcls", False),
        config.get("BlockPublicPolicy", False),
        config.get("RestrictPublicBuckets", False),
    ]

    if not all(controls):

        return {
            "id": "S3-02",
            "status": "FAIL",
            "severity": "High",
            "finding": "Public Access Protection Disabled",
            "resource": bucket_name,
            "impact": (
                "One or more S3 Public Access Block controls "
                "are disabled, increasing the chance of "
                "unintended public bucket or object exposure."
            ),
            "remediation": (
                "Enable all four Public Access Block controls."
            ),
            "evidence": (
                f"S3 Public Access Block configuration "
                f"for {bucket_name}: {config}"
            ),
        }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "S3-02",
        "status": "PASS",
        "severity": "High",
        "finding": "Public Access Protection Disabled",
        "resource": bucket_name,
        "impact": (
            "All S3 Public Access Block controls are enabled, "
            "reducing the risk of accidental public exposure."
        ),
        "remediation": (
            "Continue keeping all four Public Access Block "
            "controls enabled."
        ),
        "evidence": (
            f"All four Public Access Block controls are "
            f"enabled for {bucket_name}."
        ),
    }


# ============================================================
# S3-03
# HTTPS Enforcement
# ============================================================

def check_s3_03():
    """
    S3-03:

    Detect whether the bucket policy enforces HTTPS transport.
    """

    bucket_name = get_application_bucket()

    # --------------------------------------------------------
    # Bucket discovery failure
    # --------------------------------------------------------

    if not bucket_name:

        return {
            "id": "S3-03",
            "status": "ERROR",
            "severity": "Medium",
            "finding": "HTTPS Not Enforced",
            "resource": "Application S3 bucket",
            "impact": (
                "The scanner could not identify the "
                "project application bucket."
            ),
            "remediation": (
                "Ensure the application bucket has the "
                "required project tags."
            ),
            "evidence": (
                "No project-tagged application bucket "
                "was discovered."
            ),
        }

    # --------------------------------------------------------
    # Get bucket policy
    # --------------------------------------------------------

    policy = get_bucket_policy(bucket_name)

    if policy is None:

        return {
            "id": "S3-03",
            "status": "FAIL",
            "severity": "Medium",
            "finding": "HTTPS Not Enforced",
            "resource": bucket_name,
            "impact": (
                "The bucket does not have a policy condition "
                "requiring secure HTTPS transport."
            ),
            "remediation": (
                "Add an S3 bucket policy Deny statement "
                "using aws:SecureTransport=false to reject "
                "insecure requests."
            ),
            "evidence": (
                f"No bucket policy enforcing "
                f"aws:SecureTransport was detected "
                f"for {bucket_name}."
            ),
        }

    # --------------------------------------------------------
    # Analyze policy
    # --------------------------------------------------------

    statements = policy.get(
        "Statement",
        []
    )

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        condition = statement.get(
            "Condition",
            {}
        )

        condition_text = json.dumps(
            condition
        )

        # ----------------------------------------------------
        # Detect SecureTransport condition
        # ----------------------------------------------------

        if "aws:SecureTransport" in condition_text:

            return {
                "id": "S3-03",
                "status": "PASS",
                "severity": "Medium",
                "finding": "HTTPS Not Enforced",
                "resource": bucket_name,
                "impact": (
                    "S3 requests are protected against "
                    "insecure non-HTTPS transport."
                ),
                "remediation": (
                    "Continue enforcing aws:SecureTransport "
                    "for application bucket access."
                ),
                "evidence": (
                    f"Bucket policy for {bucket_name} "
                    f"contains an aws:SecureTransport condition."
                ),
            }

    # --------------------------------------------------------
    # SecureTransport condition not found
    # --------------------------------------------------------

    return {
        "id": "S3-03",
        "status": "FAIL",
        "severity": "Medium",
        "finding": "HTTPS Not Enforced",
        "resource": bucket_name,
        "impact": (
            "The bucket policy does not explicitly enforce "
            "secure HTTPS transport for requests."
        ),
        "remediation": (
            "Add a Deny statement using "
            "aws:SecureTransport=false to reject "
            "insecure requests."
        ),
        "evidence": (
            f"No aws:SecureTransport condition found "
            f"in the policy for {bucket_name}."
        ),
    }


# ============================================================
# Run All S3 Checks
# ============================================================

def run_s3_checks():

    return [
        check_s3_01(),
        check_s3_02(),
        check_s3_03(),
    ]


# ============================================================
# Standalone Execution
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("S3 SECURITY CHECKS")
    print("=" * 60)

    results = run_s3_checks()

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
    print("S3 security checks complete")
    print("=" * 60)
