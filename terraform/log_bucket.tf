resource "random_id" "suffix" {
  byte_length = 4
}
resource "aws_s3_bucket" "cowrie_logs" {
  bucket = "cowrie-vector-logs-${random_id.suffix.hex}"
  tags = {
    Project = "Aegis"
  }
}
resource "aws_s3_bucket_public_access_block" "cowrie_logs_access" {
  bucket                  = aws_s3_bucket.cowrie_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "cowrie_logs_encryption" {
  bucket = aws_s3_bucket.cowrie_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_iam_user" "sensor_user" {
  name = "aegis-sensor-service-account"
}
resource "aws_iam_access_key" "sensor_key" {
  user = aws_iam_user.sensor_user.name
}
resource "aws_iam_user_policy" "sensor_upload_policy" {
  name = "AegisS3UploadOnly"
  user = aws_iam_user.sensor_user.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:PutObject", "s3:GetBucketLocation"]
        Effect   = "Allow"
        Resource = ["${aws_s3_bucket.cowrie_logs.arn}/*", "${aws_s3_bucket.cowrie_logs.arn}"]
      }
    ]
  })
}
output "bucket_name" {
  value = aws_s3_bucket.cowrie_logs.id
}
output "s3_access_key" {
  value     = aws_iam_access_key.sensor_key.id
  sensitive = true
}
output "s3_secret_key" {
  value     = aws_iam_access_key.sensor_key.secret
  sensitive = true
}
