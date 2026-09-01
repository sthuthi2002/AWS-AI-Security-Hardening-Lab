variable "aws_region" {
  description = "AWS region for the security hardening lab"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix for lab resources"
  type        = string
  default     = "AI-Security-Lab-Terraform"
}

variable "instance_type" {
  description = "EC2 instance type used for the lab"
  type        = string
  default     = "t3.micro"
}
