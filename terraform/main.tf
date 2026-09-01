data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}


# ============================================================
# VPC / NETWORKING
# ============================================================

resource "aws_vpc" "lab" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-VPC"
  }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id

  tags = {
    Name = "${var.project_name}-IGW"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-Public-Subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = {
    Name = "${var.project_name}-Public-Route-Table"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}


# ============================================================
# INTENTIONALLY VULNERABLE SECURITY GROUP
# ============================================================

resource "aws_security_group" "vulnerable" {
  name        = "${var.project_name}-Vulnerable-SG"
  description = "Intentionally vulnerable security group for security assessment"
  vpc_id      = aws_vpc.lab.id

  # INTENTIONAL VULNERABILITY:
  # SSH exposed to the entire IPv4 internet.
  ingress {
    description = "INTENTIONAL: SSH exposed to internet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP for lab demonstration"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Outbound internet access for lab"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-Vulnerable-SG"
  }
}


# ============================================================
# VULNERABLE IAM ROLE
# ============================================================

resource "aws_iam_role" "vulnerable_app" {
  name = "${var.project_name}-Vulnerable-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          AWS = "*"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-Vulnerable-Role"
  }
}


resource "aws_iam_role_policy" "vulnerable_app" {
  name = "${var.project_name}-Vulnerable-Policy"
  role = aws_iam_role.vulnerable_app.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid      = "IntentionalExcessivePermissions"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}


# ============================================================
# GENERATIVE-AI WORKLOAD ROLE
# ============================================================

resource "aws_iam_role" "ai_workload" {
  name = "${var.project_name}-AI-Workload-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Effect = "Allow"

        Principal = {
          AWS = "*"
        }

        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-AI-Workload-Role"
  }
}


# AI-01: intentionally excessive permissions
resource "aws_iam_role_policy" "ai_workload_vulnerable" {
  name = "${var.project_name}-AI-Workload-Vulnerable-Policy"
  role = aws_iam_role.ai_workload.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid      = "IntentionalAIExcessivePermissions"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}


# ============================================================
# S3 - INTENTIONALLY VULNERABLE APPLICATION DATA
# ============================================================

resource "aws_s3_bucket" "application_data" {
  bucket_prefix = "ai-security-lab-data-"

  tags = {
    Name = "${var.project_name}-Application-Data"
  }
}


# AI-02 / S3-01:
# Intentionally broad data access and public bucket policy.
resource "aws_s3_bucket_policy" "vulnerable" {
  bucket = aws_s3_bucket.application_data.id

  depends_on = [
    aws_s3_bucket_public_access_block.vulnerable
  ]

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid       = "IntentionalPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.application_data.arn}/*"
      }
    ]
  })
}


# INTENTIONAL VULNERABILITY:
# All Public Access Block protections disabled.
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.application_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}


# ============================================================
# SECRETS MANAGER
# ============================================================

resource "aws_secretsmanager_secret" "application" {
  name = "${var.project_name}-Dummy-Credential"

  description = "Dummy lab secret. Contains no real credentials."

  tags = {
    Name = "${var.project_name}-Dummy-Credential"
  }
}


# ============================================================
# EC2 - INTENTIONALLY PUBLIC + UNENCRYPTED EBS
# ============================================================

resource "aws_instance" "vulnerable" {
  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.vulnerable.id]
  associate_public_ip_address = true

  iam_instance_profile = aws_iam_instance_profile.vulnerable.name

  root_block_device {
    # INTENTIONAL VULNERABILITY:
    # Encryption at rest disabled.
    encrypted             = false
    volume_size           = 8
    delete_on_termination = true
  }

  tags = {
    Name = "${var.project_name}-Vulnerable-EC2"
  }
}


resource "aws_iam_instance_profile" "vulnerable" {
  name = "${var.project_name}-Instance-Profile"
  role = aws_iam_role.vulnerable_app.name
}


# ============================================================
# CLOUDTRAIL - INTENTIONALLY WEAK CONFIGURATION
# ============================================================

resource "aws_s3_bucket" "cloudtrail" {
  bucket_prefix = "ai-security-lab-cloudtrail-"

  tags = {
    Name = "${var.project_name}-CloudTrail"
  }
}


resource "aws_cloudtrail" "lab" {
  name                          = "${var.project_name}-Trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true

  # INTENTIONAL WEAK CONFIGURATION
  enable_log_file_validation = false
  is_multi_region_trail      = false

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]
}


resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/*"

        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}
