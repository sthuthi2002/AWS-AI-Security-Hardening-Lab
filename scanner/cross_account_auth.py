import os
import boto3
from botocore.exceptions import ClientError


def configure_aws_session():
    """
    Configure boto3 authentication for the security scanner.

    When CROSS_ACCOUNT_ENABLED=true, the scanner:
      1. Uses the current AWS identity as the source identity.
      2. Calls STS AssumeRole.
      3. Configures boto3 with the temporary target-account credentials.

    No credentials are written to disk.
    """

    region = (
        os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or "us-east-1"
    )

    cross_account_enabled = (
        os.getenv("CROSS_ACCOUNT_ENABLED", "false").lower()
        == "true"
    )

    role_arn = os.getenv("CROSS_ACCOUNT_ROLE_ARN")
    session_name = os.getenv(
        "ROLE_SESSION_NAME",
        "AI-Security-Scanner"
    )

    duration = int(
        os.getenv("ROLE_DURATION_SECONDS", "3600")
    )

    # Use the existing AWS CLI/profile credentials as the source.
    profile = (
        os.getenv("AWS_PROFILE")
        or os.getenv("SCANNER_AWS_PROFILE")
    )

    if profile:
        source_session = boto3.Session(
            profile_name=profile,
            region_name=region
        )
    else:
        source_session = boto3.Session(
            region_name=region
        )

    sts = source_session.client("sts")

    source_identity = sts.get_caller_identity()

    source_account = source_identity["Account"]
    source_arn = source_identity["Arn"]

    # Normal single-account mode
    if not cross_account_enabled:
        boto3.setup_default_session(
            region_name=region
        )

        return {
            "mode": "single-account",
            "region": region,
            "source_account": source_account,
            "source_arn": source_arn,
            "target_account": source_account,
            "assumed_role": None
        }

    if not role_arn:
        raise RuntimeError(
            "CROSS_ACCOUNT_ROLE_ARN must be set when "
            "CROSS_ACCOUNT_ENABLED=true"
        )

    print("Authenticating using cross-account STS AssumeRole...")
    print(f"Source account : {source_account}")
    print(f"Source identity: {source_arn}")
    print(f"Target role    : {role_arn}")

    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=duration
        )
    except ClientError as exc:
        raise RuntimeError(
            f"Cross-account AssumeRole failed: {exc}"
        ) from exc

    credentials = response["Credentials"]

    # Configure boto3 using temporary credentials.
    boto3.setup_default_session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region
    )

    # Verify the identity after assuming the role.
    target_sts = boto3.client("sts")
    target_identity = target_sts.get_caller_identity()

    return {
        "mode": "cross-account",
        "region": region,
        "source_account": source_account,
        "source_arn": source_arn,
        "target_account": target_identity["Account"],
        "target_arn": target_identity["Arn"],
        "assumed_role": role_arn
    }
