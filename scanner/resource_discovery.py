import boto3


# ============================================================
# Project Identification
# ============================================================

PROJECT_TAG_KEY = "Project"
PROJECT_TAG_VALUE = "AWS-AI-Security-Hardening-Lab"

AI_COMPONENT = "AI-Application"
AI_DATA_COMPONENT = "AI-Application-Data"


# ============================================================
# AWS Clients
# ============================================================

def get_session():
    """
    Create a boto3 session using the AWS CLI/environment
    credentials already configured on the system.
    """
    return boto3.DEFAULT_SESSION


def get_ec2_client():
    """Return an EC2 client."""
    return get_session().client("ec2")


def get_s3_client():
    """Return an S3 client."""
    return get_session().client("s3")


def get_iam_client():
    """Return an IAM client."""
    return get_session().client("iam")


# ============================================================
# Helper: Convert AWS tags to dictionary
# ============================================================

def tags_to_dict(tags):
    """
    Convert AWS tag lists into a simple dictionary.

    Example:
        [
            {"Key": "Project", "Value": "AWS-AI-Security-Hardening-Lab"},
            {"Key": "Component", "Value": "AI-Application"}
        ]

    becomes:

        {
            "Project": "AWS-AI-Security-Hardening-Lab",
            "Component": "AI-Application"
        }
    """

    return {
        tag["Key"]: tag["Value"]
        for tag in tags or []
        if "Key" in tag and "Value" in tag
    }


# ============================================================
# EC2 Discovery
# ============================================================

def discover_lab_instances():
    """
    Discover EC2 instances belonging to this project.

    Discovery is based on the Project tag rather than
    hard-coded EC2 instance IDs.
    """

    ec2 = get_ec2_client()

    response = ec2.describe_instances(
        Filters=[
            {
                "Name": f"tag:{PROJECT_TAG_KEY}",
                "Values": [PROJECT_TAG_VALUE],
            },
            {
                "Name": "instance-state-name",
                "Values": [
                    "pending",
                    "running",
                    "stopping",
                    "stopped",
                ],
            },
        ]
    )

    instances = []

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instances.append(instance)

    return instances


# ============================================================
# S3 Application Bucket Discovery
# ============================================================

def discover_application_bucket():
    """
    Discover the S3 bucket used by the AI application.

    The bucket must have:

        Project   = AWS-AI-Security-Hardening-Lab
        Component = AI-Application-Data

    Returns:
        Bucket name if found.
        None if no matching bucket exists.
    """

    s3 = get_s3_client()

    response = s3.list_buckets()

    for bucket in response.get("Buckets", []):

        bucket_name = bucket["Name"]

        try:
            tagging = s3.get_bucket_tagging(
                Bucket=bucket_name
            )

            tags = tags_to_dict(
                tagging.get("TagSet", [])
            )

            if (
                tags.get(PROJECT_TAG_KEY) == PROJECT_TAG_VALUE
                and tags.get("Component") == AI_DATA_COMPONENT
            ):
                return bucket_name

        except Exception as e:

            error_code = (
                getattr(e, "response", {})
                .get("Error", {})
                .get("Code")
            )

            # Some S3 buckets have no tagging configuration.
            # That is not an error for discovery.
            if error_code == "NoSuchTagSet":
                continue

            # Ignore buckets that cannot be inspected.
            print(
                f"Warning: could not inspect tags for "
                f"{bucket_name}: {error_code}"
            )

            continue

    return None


# ============================================================
# IAM AI Workload Role Discovery
# ============================================================

def discover_ai_role():
    """
    Discover the IAM role belonging to the AI application.

    The role must have:

        Project   = AWS-AI-Security-Hardening-Lab
        Component = AI-Application

    Returns:
        IAM role name if found.
        None if no matching role exists.
    """

    iam = get_iam_client()

    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():

        for role in page.get("Roles", []):

            role_name = role["RoleName"]

            try:
                response = iam.list_role_tags(
                    RoleName=role_name
                )

                tags = tags_to_dict(
                    response.get("Tags", [])
                )

                if (
                    tags.get(PROJECT_TAG_KEY) == PROJECT_TAG_VALUE
                    and tags.get("Component") == AI_COMPONENT
                ):
                    return role_name

            except Exception:
                # Some roles may not be accessible.
                # Continue searching for the project role.
                continue

    return None


# ============================================================
# Combined Project Discovery
# ============================================================

def discover_project_resources():
    """
    Discover the main AWS resources belonging to the project.

    Returns a dictionary containing:

        ec2_instances
        application_bucket
        ai_role
    """

    return {
        "ec2_instances": discover_lab_instances(),
        "application_bucket": discover_application_bucket(),
        "ai_role": discover_ai_role(),
    }


# ============================================================
# Simple Discovery Test
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("AWS AI Security Hardening Lab")
    print("Resource Discovery")
    print("=" * 60)

    print("\n[EC2 INSTANCES]")

    instances = discover_lab_instances()

    if instances:

        for instance in instances:

            print(
                f"Instance ID : {instance.get('InstanceId')}"
            )

            print(
                f"Private IP  : {instance.get('PrivateIpAddress')}"
            )

            print(
                f"Public IP   : {instance.get('PublicIpAddress')}"
            )

            print()

    else:
        print("No project EC2 instances found.")

    print("[S3 APPLICATION BUCKET]")

    bucket = discover_application_bucket()

    if bucket:
        print(f"Bucket      : {bucket}")
    else:
        print("No project application bucket found.")

    print("\n[IAM AI ROLE]")

    role = discover_ai_role()

    if role:
        print(f"Role        : {role}")
    else:
        print("No project AI workload role found.")

    print("\n" + "=" * 60)
    print("Discovery complete")
    print("=" * 60)
