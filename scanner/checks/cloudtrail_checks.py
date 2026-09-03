import boto3


# ============================================================
# AWS Client
# ============================================================

def get_cloudtrail_client():
    return boto3.Session().client("cloudtrail")


# ============================================================
# Discover CloudTrail Trail
# ============================================================

def discover_cloudtrail_trail():
    """
    Discover the CloudTrail trail used by the lab.

    The scanner first looks for the project trail name.
    If it is not found, it falls back to the first
    available trail.

    This avoids hard-coding a single trail ARN/resource.
    """

    cloudtrail = get_cloudtrail_client()

    response = cloudtrail.describe_trails(
        includeShadowTrails=False
    )

    trails = response.get(
        "trailList",
        []
    )

    if not trails:
        return None

    # Prefer the lab trail if it exists.
    for trail in trails:

        trail_name = trail.get(
            "Name",
            ""
        )

        if trail_name == "AI-Security-Lab-Trail":

            return trail

    # Otherwise return the first available trail.
    return trails[0]


# ============================================================
# LOG-01
# CloudTrail Security Configuration
# ============================================================

def check_log_01():
    """
    LOG-01:

    Detect weak CloudTrail security configuration.

    Required:

        LogFileValidationEnabled = True
        IsMultiRegionTrail       = True
        LoggingEnabled           = True
        S3BucketName             configured
    """

    cloudtrail = get_cloudtrail_client()

    # --------------------------------------------------------
    # Discover trail
    # --------------------------------------------------------

    trail = discover_cloudtrail_trail()

    if trail is None:

        return {
            "id": "LOG-01",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Weak CloudTrail Security Configuration"
            ),
            "resource": "CloudTrail",
            "impact": (
                "No CloudTrail trail was discovered, "
                "reducing the ability to audit AWS activity."
            ),
            "remediation": (
                "Create and configure a CloudTrail trail "
                "with multi-region logging, log file validation, "
                "and an S3 destination."
            ),
            "evidence": (
                "No CloudTrail trail was found."
            ),
        }

    trail_name = trail.get(
        "Name",
        "Unknown"
    )

    issues = []

    # --------------------------------------------------------
    # Log file validation
    # --------------------------------------------------------

    if not trail.get(
        "LogFileValidationEnabled",
        False
    ):

        issues.append(
            "log file validation disabled"
        )

    # --------------------------------------------------------
    # Multi-region logging
    # --------------------------------------------------------

    if not trail.get(
        "IsMultiRegionTrail",
        False
    ):

        issues.append(
            "multi-region logging disabled"
        )

    # --------------------------------------------------------
    # S3 destination
    # --------------------------------------------------------

    if not trail.get(
        "S3BucketName"
    ):

        issues.append(
            "S3 logging destination not configured"
        )

    # --------------------------------------------------------
    # Check whether logging is active
    # --------------------------------------------------------

    try:

        status = cloudtrail.get_trail_status(
            Name=trail_name
        )

        if not status.get(
            "IsLogging",
            False
        ):

            issues.append(
                "CloudTrail logging is disabled"
            )

    except Exception as e:

        issues.append(
            f"unable to verify logging status: {e}"
        )

    # --------------------------------------------------------
    # Vulnerability found
    # --------------------------------------------------------

    if issues:

        return {
            "id": "LOG-01",
            "status": "FAIL",
            "severity": "High",
            "finding": (
                "Weak CloudTrail Security Configuration"
            ),
            "resource": trail_name,
            "impact": (
                "Weak CloudTrail configuration can reduce "
                "the reliability, coverage, or integrity "
                "of security audit logs."
            ),
            "remediation": (
                "Enable log file validation, configure "
                "multi-region logging, keep CloudTrail "
                "logging enabled, and use an S3 destination."
            ),
            "evidence": (
                "; ".join(issues)
            ),
        }

    # --------------------------------------------------------
    # Secure
    # --------------------------------------------------------

    return {
        "id": "LOG-01",
        "status": "PASS",
        "severity": "High",
        "finding": (
            "Weak CloudTrail Security Configuration"
        ),
        "resource": trail_name,
        "impact": (
            "CloudTrail is configured with log validation, "
            "multi-region logging, active logging, and "
            "an S3 destination."
        ),
        "remediation": (
            "Continue maintaining secure CloudTrail "
            "configuration and protected log storage."
        ),
        "evidence": (
            "Log validation, multi-region logging, "
            "active logging, and S3 log delivery are enabled."
        ),
    }


# ============================================================
# Run CloudTrail Checks
# ============================================================

def run_cloudtrail_checks():

    return [
        check_log_01()
    ]


# ============================================================
# Standalone Execution
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CLOUDTRAIL SECURITY CHECKS")
    print("=" * 60)

    results = run_cloudtrail_checks()

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
    print("CloudTrail security checks complete")
    print("=" * 60)
