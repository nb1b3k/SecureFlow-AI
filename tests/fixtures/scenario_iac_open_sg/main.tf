# Vulnerable Terraform — IaC eval fixture for an exposed security group.
#
# Intended Checkov failures:
#   - CKV_AWS_24  — SG with 0.0.0.0/0 ingress on port 22 (SSH)
#   - CKV_AWS_25  — SG with 0.0.0.0/0 ingress on port 3389 (RDP)
#   - CKV_AWS_260 — SG with 0.0.0.0/0 ingress on any port (generalised)

resource "aws_security_group" "ssh_world" {
  name        = "secureflow-eval-ssh-world"
  description = "Demo: SSH open to the world."

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
