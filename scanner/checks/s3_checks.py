import boto3
import json


BUCKET_NAME = "ai-security-lab-data-256148542278"


def get_bucket_policy():
    s3 = boto3.client("s3")

    try:
        response = s3.get_bucket_policy(
            Bucket=BUCKET_NAME
        )

        return json.loads(response["Policy"])

    except s3.exceptions.NoSuchBucket:
        return None

    except s3.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")

        if error_code == "NoSuchBucketPolicy":
            return None

        raise


def check_s3_01():
    """
    S3-01:
    Detect public access to application data.
    """

    policy = get_bucket_policy()

    if policy is None:
        return {
            "id": "S3-01",
            "status": "PASS",
            "severity": "Critical",
            "finding": "Public Application Data",
            "resource": BUCKET_NAME,
            "impact": (
                "No bucket policy was found that grants public access "
                "to application data."
            ),
            "remediation": (
                "Maintain private bucket access and ensure that no "
                "public Allow policy grants access to application objects."
            ),
            "evidence": (
                f"No bucket policy allowing public object access "
                f"was detected for {BUCKET_NAME}."
            )
        }

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        effect = statement.get("Effect")
        principal = statement.get("Principal")
        action = statement.get("Action")

        # Principal=* is dangerous in an Allow statement.
        # It can be legitimate in a Deny statement, such as
        # a policy enforcing HTTPS.
        if effect != "Allow":
            continue

        public_principal = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and principal.get("AWS") == "*"
            )
        )

        if not public_principal:
            continue

        actions = (
            action
            if isinstance(action, list)
            else [action]
        )

        for current_action in actions:

            if current_action in [
                "s3:GetObject",
                "s3:*",
                "*"
            ]:

                return {
                    "id": "S3-01",
                    "status": "FAIL",
                    "severity": "Critical",
                    "finding": "Public Application Data",
                    "resource": BUCKET_NAME,
                    "impact": (
                        "Unauthenticated or publicly accessible users "
                        "could retrieve application data from the S3 bucket."
                    ),
                    "remediation": (
                        "Remove public Allow permissions and restrict "
                        "bucket access to authorized AWS principals."
                    ),
                    "evidence": (
                        f"Bucket {BUCKET_NAME} contains an Allow statement "
                        "that grants public object access."
                    )
                }

    return {
        "id": "S3-01",
        "status": "PASS",
        "severity": "Critical",
        "finding": "Public Application Data",
        "resource": BUCKET_NAME,
        "impact": (
            "Application data is not publicly accessible through "
            "the bucket policy."
        ),
        "remediation": (
            "Continue restricting bucket access to authorized principals."
        ),
        "evidence": (
            f"No public Allow statement detected for {BUCKET_NAME}."
        )
    }


def check_s3_02():
    """
    S3-02:
    Detect missing or incomplete S3 Public Access Block protection.
    """

    s3 = boto3.client("s3")

    try:
        config = s3.get_public_access_block(
            Bucket=BUCKET_NAME
        )["PublicAccessBlockConfiguration"]

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {
            "id": "S3-02",
            "status": "FAIL",
            "severity": "High",
            "finding": "Public Access Protection Disabled",
            "resource": BUCKET_NAME,
            "impact": (
                "The bucket does not have S3 Public Access Block "
                "protection configured, increasing the risk of "
                "accidental public exposure."
            ),
            "remediation": (
                "Enable all four S3 Public Access Block controls: "
                "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                "and RestrictPublicBuckets."
            ),
            "evidence": (
                f"No Public Access Block configuration was found "
                f"for {BUCKET_NAME}."
            )
        }

    controls = [
        config.get("BlockPublicAcls", False),
        config.get("IgnorePublicAcls", False),
        config.get("BlockPublicPolicy", False),
        config.get("RestrictPublicBuckets", False)
    ]

    if not all(controls):

        return {
            "id": "S3-02",
            "status": "FAIL",
            "severity": "High",
            "finding": "Public Access Protection Disabled",
            "resource": BUCKET_NAME,
            "impact": (
                "One or more S3 Public Access Block controls are "
                "disabled, increasing the chance of unintended "
                "public bucket or object exposure."
            ),
            "remediation": (
                "Enable all four Public Access Block controls."
            ),
            "evidence": (
                f"S3 Public Access Block configuration for "
                f"{BUCKET_NAME}: {config}"
            )
        }

    return {
        "id": "S3-02",
        "status": "PASS",
        "severity": "High",
        "finding": "Public Access Protection Disabled",
        "resource": BUCKET_NAME,
        "impact": (
            "All S3 Public Access Block controls are enabled, "
            "reducing the risk of accidental public exposure."
        ),
        "remediation": (
            "Continue keeping all four Public Access Block controls enabled."
        ),
        "evidence": (
            f"All four Public Access Block controls are enabled "
            f"for {BUCKET_NAME}."
        )
    }


def check_s3_03():
    """
    S3-03:
    Detect whether bucket policy enforces HTTPS transport.
    """

    policy = get_bucket_policy()

    if policy is None:
        return {
            "id": "S3-03",
            "status": "FAIL",
            "severity": "Medium",
            "finding": "HTTPS Not Enforced",
            "resource": BUCKET_NAME,
            "impact": (
                "The bucket does not have a policy condition requiring "
                "secure HTTPS transport."
            ),
            "remediation": (
                "Add an S3 bucket policy Deny statement using "
                "aws:SecureTransport=false to reject insecure requests."
            ),
            "evidence": (
                f"No bucket policy enforcing aws:SecureTransport "
                f"was detected for {BUCKET_NAME}."
            )
        }

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:

        condition = statement.get("Condition", {})

        condition_text = json.dumps(condition)

        if "aws:SecureTransport" in condition_text:

            return {
                "id": "S3-03",
                "status": "PASS",
                "severity": "Medium",
                "finding": "HTTPS Not Enforced",
                "resource": BUCKET_NAME,
                "impact": (
                    "S3 requests are protected against insecure "
                    "non-HTTPS transport."
                ),
                "remediation": (
                    "Continue enforcing aws:SecureTransport for "
                    "application bucket access."
                ),
                "evidence": (
                    f"Bucket policy for {BUCKET_NAME} contains an "
                    "aws:SecureTransport condition."
                )
            }

    return {
        "id": "S3-03",
        "status": "FAIL",
        "severity": "Medium",
        "finding": "HTTPS Not Enforced",
        "resource": BUCKET_NAME,
        "impact": (
            "The bucket policy does not explicitly enforce secure "
            "HTTPS transport for requests."
        ),
        "remediation": (
            "Add a Deny statement using aws:SecureTransport=false "
            "to reject insecure requests."
        ),
        "evidence": (
            f"No aws:SecureTransport condition found in the "
            f"policy for {BUCKET_NAME}."
        )
    }


def run_s3_checks():
    return [
        check_s3_01(),
        check_s3_02(),
        check_s3_03()
    ]
