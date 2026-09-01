import boto3


INSTANCE_ID = "i-0f3751859f83badca"


def check_enc_01():
    """
    ENC-01:
    Detect whether the current application's root EBS volume
    is encrypted at rest.
    """

    ec2 = boto3.client("ec2")

    response = ec2.describe_instances(
        InstanceIds=[INSTANCE_ID]
    )

    instance = response["Reservations"][0]["Instances"][0]

    root_device = instance["RootDeviceName"]

    root_volume_id = None

    for mapping in instance.get("BlockDeviceMappings", []):
        if mapping.get("DeviceName") == root_device:
            root_volume_id = mapping.get("Ebs", {}).get("VolumeId")
            break

    if not root_volume_id:
        return {
            "id": "ENC-01",
            "status": "FAIL",
            "severity": "High",
            "finding": "Unencrypted EBS Volume",
            "resource": INSTANCE_ID,
            "impact": "The workload root volume could not be identified.",
            "remediation": "Ensure the EC2 workload uses an encrypted EBS root volume.",
            "evidence": "No root EBS volume was found for the instance."
        }

    response = ec2.describe_volumes(
        VolumeIds=[root_volume_id]
    )

    volume = response["Volumes"][0]

    encrypted = volume.get("Encrypted", False)

    if not encrypted:
        return {
            "id": "ENC-01",
            "status": "FAIL",
            "severity": "High",
            "finding": "Unencrypted EBS Volume",
            "resource": root_volume_id,
            "impact": (
                "Data stored on the EBS root volume is not protected "
                "by encryption at rest."
            ),
            "remediation": (
                "Replace the unencrypted root volume with an encrypted "
                "EBS volume or migrate the workload to encrypted storage."
            ),
            "evidence": (
                f"EBS volume {root_volume_id} attached to instance "
                f"{INSTANCE_ID} has encryption disabled."
            )
        }

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
            f"EBS volume {root_volume_id} attached to instance "
            f"{INSTANCE_ID} is encrypted."
        )
    }


def run_encryption_checks():
    return [check_enc_01()]
