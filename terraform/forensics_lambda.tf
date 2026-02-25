variable "forensics_bucket_name" {
  description = "The S3 bucket where malware and forensics data reside"
  type        = string
}

variable "source_folder" {
  description = "S3 prefix where raw malware is stored"
  type        = string
  default     = "evidence/malware/"
}

variable "dest_folder" {
  description = "S3 prefix where processed forensics ISOs are saved"
  type        = string
  default     = "evidence/forensics/"
}

variable "zip_password" {
  description = "Password for the encrypted ZIP file inside the ISO"
  type        = string
  default     = "infected"
}

# -------------------------------------------------------------------------
# IAM Role and Policies for Lambda
# -------------------------------------------------------------------------
resource "aws_iam_role" "lambda_forensics_role" {
  name = "lambda_forensics_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_s3_policy" {
  name        = "lambda_forensics_s3_policy"
  description = "Allows Lambda to read the malware folder and write to the forensics folder"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${var.forensics_bucket_name}"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::${var.forensics_bucket_name}/${var.source_folder}*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "arn:aws:s3:::${var.forensics_bucket_name}/${var.dest_folder}*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "s3_attach" {
  role       = aws_iam_role.lambda_forensics_role.name
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "cloudwatch_attach" {
  role       = aws_iam_role.lambda_forensics_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# -------------------------------------------------------------------------
# Lambda Function
# -------------------------------------------------------------------------
resource "aws_lambda_function" "forensics_processor" {
  filename         = "forensics_lambda.zip"
  source_code_hash = filebase64sha256("forensics_lambda.zip")
  function_name    = "MalwareForensicsProcessor"
  role             = aws_iam_role.lambda_forensics_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.10"

  # Max timeout is 15 minutes (900 seconds)
  timeout          = 900

  # Bump memory to handle larger files and ZIP/ISO generation in memory
  memory_size      = 1024

  # Expand /tmp storage to 2GB to allow downloading payloads
  ephemeral_storage {
    size = 2048
  }

  # This bridges Terraform variables directly into the Python os.environ
  environment {
    variables = {
      BUCKET_NAME   = var.forensics_bucket_name
      SOURCE_FOLDER = var.source_folder
      DEST_FOLDER   = var.dest_folder
      ZIP_PASSWORD  = var.zip_password
    }
  }
}

output "lambda_function_name" {
  value = aws_lambda_function.forensics_processor.function_name
}