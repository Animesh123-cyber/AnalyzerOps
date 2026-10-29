export interface SampleTemplate {
  id: string;
  name: string;
  description: string;
  badge: string;
  expectedFindings: number;
  code: string;
}

export const SAMPLE_TEMPLATES: SampleTemplate[] = [
  {
    id: 'vulnerable-startup',
    name: 'Vulnerable AWS Startup Stack (Terraform)',
    description: 'A typical rapidly built cloud configuration containing critical misconfigurations: public S3, wildcard IAM, open SSH/RDS ports, and unencrypted databases.',
    badge: 'Critical Violations',
    expectedFindings: 7,
    code: `# =========================================================================
# VULNERABLE STARTUP AWS INFRASTRUCTURE
# Demonstrating common DevSecOps misconfigurations across AWS resources
# =========================================================================

provider "aws" {
  region = "us-east-1"
}

# 1. Insecure S3 Bucket (Public Read ACL & Missing Server-Side Encryption)
resource "aws_s3_bucket" "customer_documents_bucket" {
  bucket = "company-sensitive-customer-docs-2026"
  acl    = "public-read" # CRITICAL: Exposes all objects to unauthenticated world

  tags = {
    Environment = "production"
    Tier        = "storage"
  }
}

# 2. Insecure IAM Policy with Wildcard Privileges
resource "aws_iam_policy" "backend_app_policy" {
  name        = "BackendWildcardServicePolicy"
  description = "Allows backend service to communicate with all AWS services"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*" # CRITICAL: Complete administrative wildcard privileges
        Resource = "*"
      }
    ]
  })
}

# 3. Direct Attachment of AdministratorAccess
resource "aws_iam_role_policy_attachment" "admin_role_attach" {
  role       = "app-production-role"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 4. Open Security Group (SSH Port 22 and PostgreSQL Port 5432 open to 0.0.0.0/0)
resource "aws_security_group" "web_and_db_sg" {
  name        = "production-default-sg"
  description = "Security group for production instances"
  vpc_id      = "vpc-0a1b2c3d4e5f67890"

  ingress {
    description = "SSH access for debugging"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # HIGH: World-accessible SSH port
  }

  ingress {
    description = "PostgreSQL direct connection"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # CRITICAL: Direct database port exposed to Internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 5. Insecure RDS Instance (Storage Unencrypted & Publicly Accessible)
resource "aws_db_instance" "primary_postgres" {
  identifier          = "prod-customer-db"
  allocated_storage   = 50
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.t3.medium"
  storage_encrypted   = false # HIGH: HIPAA / PCI-DSS failure, unencrypted at rest
  publicly_accessible = true  # CRITICAL: Database DNS endpoint is public
  skip_final_snapshot = true

  username = "master_admin"
  password = "SuperSecretDbPassword123!" # Hardcoded plaintext credential
}

# 6. EC2 Instance with IMDSv1 Enabled (SSRF Credential Theft Risk)
resource "aws_instance" "web_frontend_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  # Missing metadata_options block leaves IMDSv1 active
  # Allows SSRF exploits to steal temporary AWS credentials via 169.254.169.254

  tags = {
    Name = "prod-web-server-01"
  }
}

# 7. Unencrypted EBS Block Volume
resource "aws_ebs_volume" "app_data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false # MEDIUM: Disk volume unencrypted

  tags = {
    Name = "prod-data-volume"
  }
}
`,
  },
  {
    id: 'hardened-enterprise',
    name: 'Hardened Production AWS Architecture (CIS & SOC 2 Compliant)',
    description: 'Enterprise grade IaC template implementing defense-in-depth: S3 Block Public Access, KMS customer managed keys, IMDSv2 enforced, and strict private subnets.',
    badge: '100% Compliant',
    expectedFindings: 0,
    code: `# =========================================================================
# HARDENED ENTERPRISE AWS ARCHITECTURE
# CIS AWS Foundations Benchmark v3.0 & SOC 2 Type II Compliant
# =========================================================================

provider "aws" {
  region = "us-east-1"
}

# 1. Customer Managed KMS Key for Envelope Encryption
resource "aws_kms_key" "primary_key" {
  description             = "Dedicated Customer Managed Key for Storage Encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment = "production"
    Compliance  = "CIS-v3"
  }
}

# 2. Hardened S3 Bucket with Private ACL
resource "aws_s3_bucket" "secure_storage_bucket" {
  bucket = "enterprise-vault-storage-secure"
  acl    = "private"

  tags = {
    Environment = "production"
    DataClass   = "Confidential"
  }
}

# 3. Explicit S3 Public Access Block (CIS 2.1.5)
resource "aws_s3_bucket_public_access_block" "secure_storage_bucket_block" {
  bucket = aws_s3_bucket.secure_storage_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 4. S3 Server-Side Encryption Configuration with KMS (CIS 2.1.1)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_storage_sse" {
  bucket = aws_s3_bucket.secure_storage_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.primary_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# 5. Scoped Least-Privilege IAM Policy
resource "aws_iam_policy" "scoped_worker_policy" {
  name        = "EnterpriseScopedWorkerPolicy"
  description = "Grants least-privilege access to target bucket only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "\${aws_s3_bucket.secure_storage_bucket.arn}/*"
      }
    ]
  })
}

# 6. Hardened Security Group (No 0.0.0.0/0 on admin or database ports)
resource "aws_security_group" "private_app_sg" {
  name        = "private-workload-sg"
  description = "Strict ingress from internal VPN and private subnets only"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "Internal HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 7. Hardened RDS Database (KMS Encrypted & Private Endpoint)
resource "aws_db_instance" "hardened_postgres" {
  identifier          = "enterprise-hardened-db"
  allocated_storage   = 100
  engine              = "postgres"
  engine_version      = "15.4"
  instance_class      = "db.r6g.xlarge"
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.primary_key.arn
  publicly_accessible = false # Private subnet only
  skip_final_snapshot = false

  username = "db_admin"
  password = "REDACTED_MANAGED_BY_SECRETS_MANAGER"
}

# 8. Hardened EC2 with Enforced IMDSv2 (CIS 5.6)
resource "aws_instance" "hardened_compute_node" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m5.large"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "hardened-app-node"
  }
}

# 9. CloudTrail with Multi-Region Logging and File Integrity (CIS 3.1 & 3.2)
resource "aws_cloudtrail" "auditing_trail" {
  name                          = "enterprise-security-trail"
  s3_bucket_name                = aws_s3_bucket.secure_storage_bucket.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.primary_key.arn
}
`,
  },
  {
    id: 'kubernetes-eks-stack',
    name: 'Microservices EKS Kubernetes Stack (Terraform)',
    description: 'EKS cluster configuration testing control plane endpoint access, IAM pod roles, and secrets envelope encryption.',
    badge: 'Container Security',
    expectedFindings: 2,
    code: `# =========================================================================
# EKS KUBERNETES MICROSERVICES INFRASTRUCTURE
# =========================================================================

provider "aws" {
  region = "us-west-2"
}

# EKS Cluster with Public API Endpoint (Security Risk)
resource "aws_eks_cluster" "app_cluster" {
  name     = "microservices-prod-cluster"
  role_arn = "arn:aws:iam::123456789012:role/eks-service-role"

  vpc_config {
    subnet_ids              = ["subnet-11111111", "subnet-22222222"]
    endpoint_public_access  = true # HIGH: Public API server without CIDR restriction
    endpoint_private_access = true
  }
}

# S3 Bucket for Container Artifacts (Missing Public Access Block)
resource "aws_s3_bucket" "container_registry_cache" {
  bucket = "eks-docker-layer-cache-uswest2"
  acl    = "private"
}
`,
  },
  {
    id: 'custom-blank',
    name: '➕ Blank Workspace (Enter Your Own IaC Code)',
    description: 'Empty workspace to paste or write your custom Terraform configuration or AWS resource code for verification.',
    badge: 'Custom Input',
    expectedFindings: 0,
    code: `# Enter your custom Terraform (HCL) or AWS resource configurations below:
# Example:
# resource "aws_s3_bucket" "my_bucket" {
#   bucket = "my-custom-bucket"
#   acl    = "private"
# }

`,
  },
];
