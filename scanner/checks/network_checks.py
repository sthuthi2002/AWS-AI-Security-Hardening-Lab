"""
Network Security Checks

NET-01:
Checks whether SSH (TCP/22) is exposed to the Internet.

NET-02:
Checks whether the lab EC2 instance has a public IPv4 address.
"""

import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


# -------------------------------------------------------------------
# Project path
# -------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

LAB_INSTANCE_NAME = "AI-Security-Lab-Vulnerable-EC2"


# -------------------------------------------------------------------
# AWS Client
# -------------------------------------------------------------------

def get_ec2_client():
    """
    Create an EC2 client using the current AWS credentials.
    """
    session = boto3.DEFAULT_SESSION
    return session.client("ec2")


# -------------------------------------------------------------------
# Dynamic EC2 Discovery
# -------------------------------------------------------------------

def discover_lab_instances(ec2):
    """
    Discover the lab EC2 instances dynamically using the Name tag.

    Terminated instances are excluded.
    """

    response = ec2.describe_instances(
        Filters=[
            {
                "Name": "tag:Name",
                "Values": [LAB_INSTANCE_NAME]
            },
            {
                "Name": "instance-state-name",
                "Values": [
                    "pending",
                    "running",
                    "stopping",
                    "stopped"
                ]
            }
        ]
    )

    instances = []

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instances.append(instance)

    return instances


# -------------------------------------------------------------------
# NET-01
# -------------------------------------------------------------------

def check_net_01():
    """
    NET-01:
    Detect whether SSH (TCP/22) is exposed to the Internet.
    """

    ec2 = get_ec2_client()

    instances = discover_lab_instances(ec2)

    if not instances:
        return {
            "id": "NET-01",
            "status": "ERROR",
            "severity": "High",
            "finding": "Internet-Exposed SSH",
            "resource": "N/A",
            "impact": (
                "The lab EC2 instance could not be discovered, "
                "so its security group configuration could not "
                "be verified."
            ),
            "remediation": (
                "Verify that the lab EC2 instance exists and has "
                f"the Name tag '{LAB_INSTANCE_NAME}'."
            ),
            "evidence": (
                "No matching lab EC2 instance was found."
            )
        }

    checked_instances = []

    for instance in instances:

        instance_id = instance["InstanceId"]

        security_groups = instance.get("SecurityGroups", [])

        for sg in security_groups:

            group_id = sg.get("GroupId")

            if not group_id:
                continue

            try:

                response = ec2.describe_security_groups(
                    GroupIds=[group_id]
                )

            except ClientError as e:

                return {
                    "id": "NET-01",
                    "status": "ERROR",
                    "severity": "High",
                    "finding": "Internet-Exposed SSH",
                    "resource": group_id,
                    "impact": (
                        "The scanner could not inspect the security "
                        "group configuration."
                    ),
                    "remediation": (
                        "Verify IAM permissions for "
                        "ec2:DescribeSecurityGroups."
                    ),
                    "evidence": (
                        f"AWS API error while checking security "
                        f"group {group_id}: {e}"
                    )
                }

            groups = response.get("SecurityGroups", [])

            for group in groups:

                for permission in group.get("IpPermissions", []):

                    protocol = permission.get("IpProtocol")

                    from_port = permission.get("FromPort")
                    to_port = permission.get("ToPort")

                    # ------------------------------------------------
                    # Check TCP port 22
                    # ------------------------------------------------

                    is_ssh = (
                        protocol == "tcp"
                        and from_port == 22
                        and to_port == 22
                    )

                    if not is_ssh:
                        continue

                    for ip_range in permission.get("IpRanges", []):

                        cidr = ip_range.get("CidrIp")

                        if cidr == "0.0.0.0/0":

                            return {
                                "id": "NET-01",
                                "status": "FAIL",
                                "severity": "High",
                                "finding": (
                                    "Internet-Exposed SSH"
                                ),
                                "resource": group_id,
                                "impact": (
                                    "SSH is exposed to the entire "
                                    "Internet, allowing unrestricted "
                                    "TCP/22 access to the workload."
                                ),
                                "remediation": (
                                    "Remove the 0.0.0.0/0 SSH rule. "
                                    "Restrict administrative access "
                                    "to a trusted source or use a "
                                    "private administration mechanism "
                                    "such as AWS Systems Manager."
                                ),
                                "evidence": (
                                    f"Security group {group_id} attached "
                                    f"to instance {instance_id} allows "
                                    f"TCP/22 from 0.0.0.0/0."
                                )
                            }

    # ---------------------------------------------------------------
    # PASS
    # ---------------------------------------------------------------

    return {
        "id": "NET-01",
        "status": "PASS",
        "severity": "High",
        "finding": "Internet-Exposed SSH",
        "resource": LAB_INSTANCE_NAME,
        "impact": (
            "SSH is not exposed to the entire Internet."
        ),
        "remediation": (
            "Maintain restricted administrative access."
        ),
        "evidence": (
            "No TCP/22 security group rule allowing "
            "0.0.0.0/0 was detected."
        )
    }


# -------------------------------------------------------------------
# NET-02
# -------------------------------------------------------------------

def check_net_02():
    """
    NET-02:
    Detect whether the lab EC2 instance has a public IPv4 address.
    """

    ec2 = get_ec2_client()

    instances = discover_lab_instances(ec2)

    if not instances:
        return {
            "id": "NET-02",
            "status": "ERROR",
            "severity": "Medium",
            "finding": "Publicly Addressable EC2 Instance",
            "resource": "N/A",
            "impact": (
                "The lab EC2 instance could not be discovered, "
                "so its public IP configuration could not be verified."
            ),
            "remediation": (
                "Verify that the lab EC2 instance exists and has "
                f"the Name tag '{LAB_INSTANCE_NAME}'."
            ),
            "evidence": (
                "No matching lab EC2 instance was found."
            )
        }

    for instance in instances:

        instance_id = instance["InstanceId"]

        public_ip = instance.get("PublicIpAddress")

        # -----------------------------------------------------------
        # FAIL
        # -----------------------------------------------------------

        if public_ip:

            return {
                "id": "NET-02",
                "status": "FAIL",
                "severity": "Medium",
                "finding": (
                    "Publicly Addressable EC2 Instance"
                ),
                "resource": instance_id,
                "impact": (
                    "The EC2 workload has a public IPv4 address, "
                    "making the instance directly addressable from "
                    "the Internet."
                ),
                "remediation": (
                    "Remove the public IPv4 address and place the "
                    "workload in a private subnet. Use controlled "
                    "administrative access such as AWS Systems Manager "
                    "or a bastion host when required."
                ),
                "evidence": (
                    f"Instance {instance_id} has public IPv4 address "
                    f"{public_ip}."
                )
            }

    # ---------------------------------------------------------------
    # PASS
    # ---------------------------------------------------------------

    return {
        "id": "NET-02",
        "status": "PASS",
        "severity": "Medium",
        "finding": (
            "Publicly Addressable EC2 Instance"
        ),
        "resource": LAB_INSTANCE_NAME,
        "impact": (
            "The EC2 workload does not have a public IPv4 address."
        ),
        "remediation": (
            "Maintain private addressing for the workload."
        ),
        "evidence": (
            "No public IPv4 address was detected on the "
            "lab EC2 instance."
        )
    }


# -------------------------------------------------------------------
# Run all network checks
# -------------------------------------------------------------------

def run_network_checks():
    return [
        check_net_01(),
        check_net_02()
    ]


# -------------------------------------------------------------------
# Standalone execution
# -------------------------------------------------------------------

if __name__ == "__main__":

    results = run_network_checks()

    print("=" * 60)
    print("NETWORK SECURITY CHECKS")
    print("=" * 60)

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
    print("Network security checks complete")
    print("=" * 60)
