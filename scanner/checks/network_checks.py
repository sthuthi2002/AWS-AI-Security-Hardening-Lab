import boto3


INSTANCE_ID = "i-0f3751859f83badca"
SECURITY_GROUP_ID = "sg-032c8c60db89d1c98"


def check_net_01():
    """
    NET-01:
    Detect SSH exposed to the entire IPv4 internet.
    """

    ec2 = boto3.client("ec2")

    response = ec2.describe_security_groups(
        GroupIds=[SECURITY_GROUP_ID]
    )

    permissions = response["SecurityGroups"][0].get(
        "IpPermissions", []
    )

    for permission in permissions:

        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        # Ignore rules where ports are not defined.
        if (
            protocol != "tcp"
            or from_port is None
            or to_port is None
        ):
            continue

        # Check whether TCP/22 is included in the rule.
        if from_port <= 22 <= to_port:

            for ip_range in permission.get("IpRanges", []):

                if ip_range.get("CidrIp") == "0.0.0.0/0":

                    return {
                        "id": "NET-01",
                        "status": "FAIL",
                        "severity": "High",
                        "finding": "Internet-Exposed SSH",
                        "resource": SECURITY_GROUP_ID,
                        "impact": (
                            "SSH is reachable from the entire IPv4 "
                            "internet, increasing the risk of brute-force "
                            "attacks and unauthorized access."
                        ),
                        "remediation": (
                            "Remove the 0.0.0.0/0 SSH rule and restrict "
                            "TCP port 22 to a trusted administrative "
                            "source or private network."
                        ),
                        "evidence": (
                            f"Security group {SECURITY_GROUP_ID} allows "
                            "TCP port 22 from 0.0.0.0/0."
                        )
                    }

    return {
        "id": "NET-01",
        "status": "PASS",
        "severity": "High",
        "finding": "Internet-Exposed SSH",
        "resource": SECURITY_GROUP_ID,
        "impact": (
            "SSH is not exposed to the entire IPv4 internet."
        ),
        "remediation": (
            "Continue restricting administrative access to trusted "
            "sources."
        ),
        "evidence": (
            f"Security group {SECURITY_GROUP_ID} does not allow "
            "TCP port 22 from 0.0.0.0/0."
        )
    }


def check_net_02():
    """
    NET-02:
    Detect an EC2 workload with a public IPv4 address.
    """

    ec2 = boto3.client("ec2")

    response = ec2.describe_instances(
        InstanceIds=[INSTANCE_ID]
    )

    instance = response["Reservations"][0]["Instances"][0]

    public_ip = instance.get("PublicIpAddress")
    private_ip = instance.get("PrivateIpAddress")
    subnet_id = instance.get("SubnetId")

    if public_ip:

        return {
            "id": "NET-02",
            "status": "FAIL",
            "severity": "High",
            "finding": "Internet-Facing Application Workload",
            "resource": INSTANCE_ID,
            "impact": (
                "The EC2 workload has a public IP address, making it "
                "directly reachable from the internet and increasing "
                "the external attack surface."
            ),
            "remediation": (
                "Remove the public IP and place the workload in a "
                "private subnet. Use controlled network paths for "
                "administrative or application access."
            ),
            "evidence": (
                f"EC2 instance {INSTANCE_ID} has public IP "
                f"{public_ip} in subnet {subnet_id}."
            )
        }

    return {
        "id": "NET-02",
        "status": "PASS",
        "severity": "High",
        "finding": "Internet-Facing Application Workload",
        "resource": INSTANCE_ID,
        "impact": (
            "The EC2 workload does not have a public IP address, "
            "reducing its direct internet exposure."
        ),
        "remediation": (
            "Continue keeping the application workload private and "
            "avoid unnecessary public IP assignments."
        ),
        "evidence": (
            f"EC2 instance {INSTANCE_ID} has no public IP. "
            f"Private IP: {private_ip}, subnet: {subnet_id}."
        )
    }


def run_network_checks():
    return [
        check_net_01(),
        check_net_02()
    ]
