# Vulnerable Terraform — IaC eval fixture for the Checkov agent (W4).
#
# Intended Checkov failures:
#   - CKV_AWS_20 / CKV_AWS_53 / CKV_AWS_56 — public S3 bucket
#   - CKV_AWS_18 / CKV_AWS_19 / CKV_AWS_21 — no logging, no SSE, no versioning
#   - CKV_AWS_1 / CKV_AWS_40 — wildcard IAM policy

resource "aws_s3_bucket" "data" {
  bucket = "secureflow-eval-public-bucket"
}

resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

resource "aws_iam_policy" "admin_everything" {
  name = "secureflow-eval-admin-everything"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
