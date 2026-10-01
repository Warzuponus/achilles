# Deliberately misconfigured Terraform for Checkov to flag (CKV_AWS_* / CKV2_*).
resource "aws_s3_bucket" "example" {
  bucket = "my-insecure-bucket"
}

resource "aws_security_group" "open" {
  name = "open-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # SSH open to the world
  }
}
