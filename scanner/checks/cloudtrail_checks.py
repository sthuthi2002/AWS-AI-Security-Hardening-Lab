import boto3


TRAIL_NAME = "AI-Security-Lab-Trail"


def check_log_01():
    cloudtrail = boto3.client("cloudtrail")

    response = cloudtrail.get_trail(
        Name=TRAIL_NAME
    )

    trail = response["Trail"]

    issues = []

    if not trail.get("LogFileValidationEnabled", False):
        issues.append("log file validation disabled")

    if not trail.get("IsMultiRegionTrail", False):
        issues.append("multi-region logging disabled")

    if issues:
        return {
            "id": "LOG-01",
            "status": "FAIL",
            "severity": "High",
            "finding": "Weak CloudTrail Security Configuration",
            "evidence": "; ".join(issues)
        }

    return {
        "id": "LOG-01",
        "status": "PASS",
        "severity": "High",
        "finding": "Weak CloudTrail Security Configuration",
        "evidence": "Log validation and multi-region logging enabled"
    }


def run_cloudtrail_checks():
    return [check_log_01()]
