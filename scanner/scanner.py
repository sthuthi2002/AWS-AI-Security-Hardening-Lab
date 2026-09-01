import argparse
import json
from datetime import datetime, timezone

from scanner.checks.iam_checks import run_iam_checks
from scanner.checks.s3_checks import run_s3_checks
from scanner.checks.network_checks import run_network_checks
from scanner.checks.secrets_checks import run_secrets_checks
from scanner.checks.cloudtrail_checks import run_cloudtrail_checks
from scanner.checks.ai_checks import run_ai_checks
from scanner.checks.encryption_checks import run_encryption_checks


def run_all_checks():
    findings = []

    findings.extend(run_iam_checks())
    findings.extend(run_s3_checks())
    findings.extend(run_network_checks())
    findings.extend(run_secrets_checks())
    findings.extend(run_cloudtrail_checks())
    findings.extend(run_ai_checks())
    findings.extend(run_encryption_checks())

    return findings


def print_report(findings):
    print()
    print("=" * 70)
    print("AWS SECURITY HARDENING LAB - SECURITY SCAN")
    print("=" * 70)
    print()

    fail_count = 0
    pass_count = 0

    for finding in findings:
        status = finding["status"]

        if status == "FAIL":
            fail_count += 1
            symbol = "[FAIL]"
        else:
            pass_count += 1
            symbol = "[PASS]"

        print(
            f"{symbol} {finding['id']} | "
            f"{finding['severity']} | "
            f"{finding['finding']}"
        )

        if "resource" in finding:
            print(f"       Resource: {finding['resource']}")

        print(f"       Evidence: {finding['evidence']}")

        if "impact" in finding:
            print(f"       Impact: {finding['impact']}")

        if "remediation" in finding:
            print(f"       Remediation: {finding['remediation']}")

        print()

    print("=" * 70)
    print(f"Total checks : {len(findings)}")
    print(f"Failed       : {fail_count}")
    print(f"Passed       : {pass_count}")
    print("=" * 70)


def save_report(findings, output_path):
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(findings),
        "failed": sum(
            1
            for finding in findings
            if finding["status"] == "FAIL"
        ),
        "passed": sum(
            1
            for finding in findings
            if finding["status"] == "PASS"
        ),
        "findings": findings,
    }

    with open(output_path, "w") as file:
        json.dump(report, file, indent=2)

    print(f"\nJSON report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="AWS Security Hardening Lab scanner"
    )

    parser.add_argument(
        "--output",
        default="reports/final-scan.json",
        help="Path for the JSON scan report",
    )

    args = parser.parse_args()

    findings = run_all_checks()

    print_report(findings)
    save_report(findings, args.output)


if __name__ == "__main__":
    main()
