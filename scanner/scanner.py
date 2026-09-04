import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

from scanner.cross_account_auth import configure_aws_session

from scanner.checks.iam_checks import run_iam_checks
from scanner.checks.s3_checks import run_s3_checks
from scanner.checks.network_checks import run_network_checks
from scanner.checks.secrets_checks import run_secrets_checks
from scanner.checks.cloudtrail_checks import run_cloudtrail_checks
from scanner.checks.ai_checks import run_ai_checks
from scanner.checks.encryption_checks import run_encryption_checks


def run_all_checks():
    """Run all AWS and AI security checks."""
    results = []

    results.extend(run_iam_checks())
    results.extend(run_s3_checks())
    results.extend(run_network_checks())
    results.extend(run_secrets_checks())
    results.extend(run_cloudtrail_checks())
    results.extend(run_ai_checks())
    results.extend(run_encryption_checks())

    return results


def build_report(results, auth_info=None):
    """Build a structured security assessment report."""

    failed = sum(
        1 for result in results
        if result.get("status") == "FAIL"
    )

    passed = sum(
        1 for result in results
        if result.get("status") == "PASS"
    )

    report = {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(results),
        "failed": failed,
        "passed": passed,
        "results": results
    }

    if auth_info:
        report["authentication"] = auth_info

    return report


def print_authentication(auth_info):
    """Print authentication information."""

    print()
    print("=" * 70)
    print("AWS AUTHENTICATION")
    print("=" * 70)

    print(
        f"Authentication : "
        f"{auth_info.get('mode', 'unknown')}"
    )

    print(
        f"Region         : "
        f"{auth_info.get('region', 'unknown')}"
    )

    print(
        f"Source account : "
        f"{auth_info.get('source_account', 'unknown')}"
    )

    print(
        f"Source identity: "
        f"{auth_info.get('source_arn', 'unknown')}"
    )

    print(
        f"Target account : "
        f"{auth_info.get('target_account', 'unknown')}"
    )

    if auth_info.get("target_arn"):
        print(
            f"Target identity: "
            f"{auth_info['target_arn']}"
        )

    if auth_info.get("assumed_role"):
        print(
            f"Assumed role   : "
            f"{auth_info['assumed_role']}"
        )

    print("=" * 70)


def print_report(report):
    """Print the security scan in a readable format."""

    print()
    print("=" * 70)
    print("AWS SECURITY HARDENING LAB - SECURITY SCAN")
    print("=" * 70)
    print()

    for result in report["results"]:

        status = result.get("status", "UNKNOWN")
        check_id = result.get("id", "UNKNOWN")
        severity = result.get("severity", "Unknown")
        finding = result.get("finding", "Unknown Finding")

        print(
            f"[{status}] {check_id} | "
            f"{severity} | {finding}"
        )

        if result.get("resource"):
            print(
                f"       Resource: "
                f"{result['resource']}"
            )

        if result.get("evidence"):
            print(
                f"       Evidence: "
                f"{result['evidence']}"
            )

        if result.get("impact"):
            print(
                f"       Impact: "
                f"{result['impact']}"
            )

        if result.get("remediation"):
            print(
                f"       Remediation: "
                f"{result['remediation']}"
            )

        print()

    print("=" * 70)
    print(f"Total checks : {report['total_checks']}")
    print(f"Failed       : {report['failed']}")
    print(f"Passed       : {report['passed']}")
    print("=" * 70)


def save_report(report, output_file):
    """Save the scan report as JSON."""

    output_path = Path(output_file)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open("w") as file:
        json.dump(
            report,
            file,
            indent=2
        )

    print()
    print(f"JSON report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="AWS Security Hardening Lab Scanner"
    )

    parser.add_argument(
        "--output",
        default="reports/final-scan.json",
        help=(
            "Path to the JSON report "
            "(default: reports/final-scan.json)"
        )
    )

    args = parser.parse_args()

    try:
        # ---------------------------------------------------------
        # Cross-account authentication happens BEFORE any checks.
        # ---------------------------------------------------------
        auth_info = configure_aws_session()

        print_authentication(auth_info)

        # ---------------------------------------------------------
        # Existing security checks remain unchanged.
        # They now use the authenticated boto3 session.
        # ---------------------------------------------------------
        results = run_all_checks()

        report = build_report(
            results,
            auth_info
        )

        print_report(report)

        save_report(
            report,
            args.output
        )

    except Exception as error:
        print()
        print("=" * 70)
        print("SCAN ERROR")
        print("=" * 70)
        print(f"Error: {error}")
        print("=" * 70)
        raise


if __name__ == "__main__":
    main()
