# Combined-PR fixture: vulnerable Terraform alongside vulnerable Python +
# Dockerfile. Exercises all parallel scanner branches firing on the same
# scan target.
#
# Intended Checkov failures:
#   - CKV_AWS_1 / CKV_AWS_40 — wildcard IAM Action / Resource

resource "aws_iam_policy" "admin" {
  name = "secureflow-eval-combined-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
