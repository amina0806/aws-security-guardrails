#providers&Data#

terraform {
    required_version = ">= 1.5.0"
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = ">=5.0"
        }
    }
}

provider "aws" {
    region = var.home_region
}

###variables###

variable "home_region" {
    description = "Region to create the multi-use tail resources"
    type = string
    default = "us-east-1"
}

variable "trail_name" {
    description = "Region to create the multi-use tail resources"
    type = string
    default = "org-secure-multiregion-trail"
}

variable "s3_bucket_name" {
    description = "s3 bucket name for cloudtrail logs"
    type = string
}

### s3_bucket_cloudtrail###

resource "aws_s3_bucket" "cloudtrail" {
  bucket = var.s3_bucket_name
  force_destroy = false

  tags = {
    Name               = var.trail_name
    data_classification = "internal"
    owner               = "security"
    env                 = "prod"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "AES256"
    }
  }
}

### kMS CMK for cloudtrail log encryption

resource "aws_kms_key" "cloudtrail" {
  description             = "KMS key for CloudTrail log SSE-KMS"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Admin permissions for the account root (replace with a key admin role in real setups)
      {
        Sid      = "EnableAccountRootPermissions"
        Effect   = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/CloudSecurityAdmin"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      # Allow CloudTrail service to use the key for encrypting/decrypting delivered logs
      {
        Sid    = "AllowCloudTrailUseOfTheKey"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource  = "*"

        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.home_region}:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"
            }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"
          }
        }
      }
    ]
  })
  tags = {
    Name = "${var.trail_name}-kms"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.trail_name}"
  target_key_id = aws_kms_key.cloudtrail.key_id
}


############################
# S3 Bucket Policy for CloudTrail writes
############################
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Allow CloudTrail to get the bucket ACL (required)
      {
        Sid:    "AWSCloudTrailAclCheck",
        Effect: "Allow",
        Principal: { Service: "cloudtrail.amazonaws.com" },
        Action: "s3:GetBucketAcl",
        Resource: aws_s3_bucket.cloudtrail.arn
      },
      # Allow CloudTrail to put objects with the right ACL into the AWSLogs/<account-id>/ prefix
      {
        Sid:    "AWSCloudTrailWrite",
        Effect: "Allow",
        Principal: { Service: "cloudtrail.amazonaws.com" },
        Action: "s3:PutObject",
        Resource: "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition: {
          StringEquals: {
            "s3:x-amz-acl": "bucket-owner-full-control"
          },
          ArnLike: {
            "aws:SourceArn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/${var.trail_name}"
          }
        }
      }
    ]
  })
}

############################
# CloudTrail (multi-region, KMS-encrypted)
############################
resource "aws_cloudtrail" "this" {
  name                          = var.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  kms_key_id                    = aws_kms_key.cloudtrail.arn
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_organization_trail         = false # set true if using AWS Organizations (and you have the permissions)

  # Recommended: deliver management events; data events can be added later per need/cost
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    Name = var.trail_name
    owner = "security"
    env   = "prod"
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail,
    aws_kms_key.cloudtrail
  ]
}

############################
# Useful Outputs
############################
output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "s3_bucket" {
  value = aws_s3_bucket.cloudtrail.bucket
}

output "kms_key_arn" {
  value = aws_kms_key.cloudtrail.arn
}
