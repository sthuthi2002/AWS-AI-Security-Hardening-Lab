output "vpc_id" {
  description = "Lab VPC ID"
  value       = aws_vpc.lab.id
}

output "public_subnet_id" {
  description = "Public subnet ID"
  value       = aws_subnet.public.id
}

output "security_group_id" {
  description = "Intentionally vulnerable security group ID"
  value       = aws_security_group.vulnerable.id
}

output "application_bucket_name" {
  description = "Application data S3 bucket"
  value       = aws_s3_bucket.application_data.id
}

output "cloudtrail_bucket_name" {
  description = "CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_name" {
  description = "CloudTrail trail name"
  value       = aws_cloudtrail.lab.name
}

output "application_role_name" {
  description = "Intentionally vulnerable application IAM role"
  value       = aws_iam_role.vulnerable_app.name
}

output "ai_workload_role_name" {
  description = "Generative-AI workload IAM role"
  value       = aws_iam_role.ai_workload.name
}

output "instance_id" {
  description = "Intentionally vulnerable EC2 instance"
  value       = aws_instance.vulnerable.id
}

output "secret_name" {
  description = "Dummy Secrets Manager secret"
  value       = aws_secretsmanager_secret.application.name
}
