# Vulnerable Terraform fixture — exercises the new IaC/Checkov agent in CI.
#
# This file is intentionally insecure and ONLY exists so the PR that adds
# the IaC agent has at least one IaC-shaped change to scan. Without it the
# new agent would scope-guard out of every PR run and the bot comment
# wouldn't have any Checkov findings to display, defeating the validation.
#
# DO NOT copy this file into a real deployment. The misconfigurations are
# textbook examples of what the IaC agent is supposed to catch:
#   - Public S3 bucket (CKV_AWS_20, CKV_AWS_53, CKV_AWS_56)
#   - Wildcard IAM permissions (CKV_AWS_1, CKV_AWS_40)
#   - 0.0.0.0/0 ingress on SSH (CKV_AWS_24)

resource "aws_s3_bucket" "public" {
  bucket = "secureflow-demo-public-bucket"
  # No public_access_block, no versioning, no SSE, no logging.
}

resource "aws_s3_bucket_policy" "public" {
  bucket = aws_s3_bucket.public.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public.arn}/*"
    }]
  })
}

resource "aws_iam_policy" "wildcard" {
  name   = "secureflow-demo-wildcard"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_security_group" "ssh_open" {
  name        = "secureflow-demo-ssh-open"
  description = "Demo: SSH open to the world"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
