"""
EBS Encryption Security Checks

ENC-01:
Checks whether the root EBS volume of the lab EC2 instance
is encrypted at rest.
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
    Create an EC2 client using the current boto3/AWS CLI credentials.
    """
    session = boto3.DEFAULT_SESSION
    return session.client("ec2")


# -------------------------------------------------------------------
# Dynamic EC2 Discovery
# -------------------------------------------------------------------

def discover_lab_instances(ec2):
    """
    Discover lab EC2 instances dynamically using the Name tag.

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
# ENC-01
# -------------------------------------------------------------------

def check_enc_01():
    """
    ENC-01:
    Verify that the root EBS volume attached to the lab EC2 instance
    is encrypted.
    """

    ec2 = get_ec2_client()

    instances = discover_lab_instances(ec2)

    if not instances:
        return {
            "id": "ENC-01",
            "status": "ERROR",
            "severity": "High",
            "finding": "Unencrypted EBS Volume",
            "resource": "N/A",
            "impact": (
                "The lab EC2 instance could not be discovered, "
                "so its root EBS volume could not be verified."
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

        root_volume_id = None

        # -----------------------------------------------------------
        # Find root device
        # -----------------------------------------------------------

        for mapping in instance.get("BlockDeviceMappings", []):

            device_name = mapping.get("DeviceName", "")

            if device_name == instance.get(
                "RootDeviceName",
                "/dev/xvda"
            ):
                ebs = mapping.get("Ebs", {})

                root_volume_id = ebs.get("VolumeId")

                if root_volume_id:
                    break

        # Fallback in case RootDeviceName is not directly available
        if not root_volume_id:

            for mapping in instance.get("BlockDeviceMappings", []):

                if mapping.get("DeviceName") == "/dev/xvda":

                    ebs = mapping.get("Ebs", {})

                    root_volume_id = ebs.get("VolumeId")

                    if root_volume_id:
                        break

        # -----------------------------------------------------------
        # Root volume not found
        # -----------------------------------------------------------

        if not root_volume_id:

            return {
                "id": "ENC-01",
                "status": "ERROR",
                "severity": "High",
                "finding": "Unencrypted EBS Volume",
                "resource": instance_id,
                "impact": (
                    "The root EBS volume could not be identified, "
                    "so encryption status could not be verified."
                ),
                "remediation": (
                    "Verify that the EC2 instance has a valid "
                    "root EBS volume."
                ),
                "evidence": (
                    f"No root EBS volume was found for instance "
                    f"{instance_id}."
                )
            }

        # -----------------------------------------------------------
        # Check EBS encryption
        # -----------------------------------------------------------

        try:

            response = ec2.describe_volumes(
                VolumeIds=[root_volume_id]
            )

            volumes = response.get("Volumes", [])

            if not volumes:

                return {
                    "id": "ENC-01",
                    "status": "ERROR",
                    "severity": "High",
                    "finding": "Unencrypted EBS Volume",
                    "resource": root_volume_id,
                    "impact": (
                        "The root EBS volume could not be retrieved "
                        "for encryption verification."
                    ),
                    "remediation": (
                        "Verify that the root EBS volume exists."
                    ),
                    "evidence": (
                        f"EBS volume {root_volume_id} could not "
                        f"be retrieved."
                    )
                }

            volume = volumes[0]

            encrypted = volume.get("Encrypted", False)

        except ClientError as e:

            return {
                "id": "ENC-01",
                "status": "ERROR",
                "severity": "High",
                "finding": "Unencrypted EBS Volume",
                "resource": root_volume_id,
                "impact": (
                    "The scanner could not determine whether "
                    "the root EBS volume is encrypted."
                ),
                "remediation": (
                    "Verify IAM permissions for "
                    "ec2:DescribeVolumes."
                ),
                "evidence": (
                    f"AWS API error while checking volume "
                    f"{root_volume_id}: {e}"
                )
            }

        # -----------------------------------------------------------
        # FAIL
        # -----------------------------------------------------------

        if not encrypted:

            return {
                "id": "ENC-01",
                "status": "FAIL",
                "severity": "High",
                "finding": "Unencrypted EBS Volume",
                "resource": root_volume_id,
                "impact": (
                    "The workload root volume is not encrypted "
                    "at rest, increasing the risk of data exposure "
                    "if the underlying storage is compromised."
                ),
                "remediation": (
                    "Create an encrypted replacement EBS volume "
                    "from a snapshot and attach it as the root "
                    "volume. Maintain encryption for all workload "
                    "storage."
                ),
                "evidence": (
                    f"EBS volume {root_volume_id} attached to "
                    f"instance {instance_id} has encryption disabled."
                )
            }

        # -----------------------------------------------------------
        # PASS
        # -----------------------------------------------------------

        return {
            "id": "ENC-01",
            "status": "PASS",
            "severity": "High",
            "finding": "Unencrypted EBS Volume",
            "resource": root_volume_id,
            "impact": (
                "The workload root volume is protected using "
                "encryption at rest."
            ),
            "remediation": (
                "Maintain encryption for the workload's EBS storage."
            ),
            "evidence": (
                f"EBS volume {root_volume_id} attached to "
                f"instance {instance_id} is encrypted."
            )
        }


# -------------------------------------------------------------------
# Run encryption checks
# -------------------------------------------------------------------

def run_encryption_checks():
    return [check_enc_01()]


# -------------------------------------------------------------------
# Standalone execution
# -------------------------------------------------------------------

if __name__ == "__main__":

    results = run_encryption_checks()

    print("=" * 60)
    print("ENCRYPTION SECURITY CHECKS")
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
    print("Encryption security checks complete")
    print("=" * 60)
