import { SecurityRuleDefinition, ResourceBlock } from '../types/cspm';

export const CSPM_RULES: SecurityRuleDefinition[] = [
  // 1. S3 Public Access Block Missing
  {
    id: 'RULE_S3_BLOCK_PUBLIC_ACCESS',
    ruleCode: 'CKV_AWS_53',
    title: 'S3 Bucket Missing Public Access Block Configuration',
    description: 'Ensure S3 buckets have Amazon S3 Block Public Access enabled at the bucket level to prevent unauthorized public exposure.',
    resourceType: 'aws_s3_bucket',
    severity: 'HIGH',
    cvssScore: 8.2,
    compliance: {
      cis: ['CIS AWS 2.1.5', 'CIS AWS 2.1.1'],
      soc2: ['CC6.1', 'CC6.6'],
      hipaa: ['164.312(a)(1)'],
      pci: ['PCI-DSS 1.3', 'PCI-DSS 7.1'],
      nist: ['AC-3', 'AC-6', 'SC-7'],
    },
    impact: 'Without Block Public Access, bucket policies or ACLs could mistakenly expose sensitive internal documents or customer PII to the public Internet.',
    check: (block, allBlocks) => {
      // Check if there is an associated aws_s3_bucket_public_access_block targeting this bucket
      const hasBlockConfig = allBlocks.some(
        (b) =>
          b.rawType === 'aws_s3_bucket_public_access_block' &&
          (b.rawText.includes(block.name) ||
            b.properties['bucket'] === block.name ||
            b.rawText.includes(`aws_s3_bucket.${block.name}.id`))
      );
      if (!hasBlockConfig && !block.rawText.includes('block_public_acls = true')) {
        return {
          failed: true,
          message: `Bucket "${block.name}" does not declare an aws_s3_bucket_public_access_block resource.`,
        };
      }
      return false;
    },
    remediationAdvice: 'Add an aws_s3_bucket_public_access_block resource with block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets set to true.',
    remediationSnippet: `resource "aws_s3_bucket_public_access_block" "remediated_access_block" {
  bucket = aws_s3_bucket.TARGET_BUCKET.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
    boto3Snippet: (block) => `import boto3

s3 = boto3.client('s3')
s3.put_public_access_block(
    Bucket='${block.properties.bucket || block.name}',
    PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
    }
)`,
    awsCliSnippet: (block) => `aws s3api put-public-access-block --bucket ${block.properties.bucket || block.name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"`,
  },

  // 2. S3 Public ACL (Critical / High)
  {
    id: 'RULE_S3_PUBLIC_ACL',
    ruleCode: 'CKV_AWS_20',
    title: 'S3 Bucket Configured with Public Read or Write ACL',
    description: 'Ensure S3 buckets do not use public-read, public-read-write, or authenticated-read Canned ACLs.',
    resourceType: 'aws_s3_bucket',
    severity: 'CRITICAL',
    cvssScore: 9.6,
    compliance: {
      cis: ['CIS AWS 2.1.5'],
      soc2: ['CC6.1', 'CC6.3'],
      hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
      pci: ['PCI-DSS 1.3', 'PCI-DSS 7.1'],
      nist: ['AC-3', 'MP-5'],
    },
    impact: 'Direct unauthenticated public reads and writes permit threat actors to scrape private data or inject malicious payloads into data pipelines.',
    check: (block) => {
      const acl = block.properties['acl'];
      if (typeof acl === 'string') {
        const lower = acl.toLowerCase();
        if (lower.includes('public-read') || lower.includes('public-read-write') || lower.includes('authenticated-read')) {
          return { failed: true, message: `Bucket ACL set to insecure "${acl}".` };
        }
      }
      if (block.rawText.match(/acl\s*=\s*"(public-read|public-read-write|authenticated-read)"/i)) {
        return { failed: true, message: 'Bucket uses public read/write ACL.' };
      }
      return false;
    },
    remediationAdvice: 'Change the bucket ACL to "private" or adopt S3 Object Ownership (BucketOwnerEnforced) to disable ACLs altogether.',
    remediationSnippet: `  acl = "private"`,
    boto3Snippet: (block) => `import boto3

s3 = boto3.client('s3')
s3.put_bucket_acl(
    Bucket='${block.properties.bucket || block.name}',
    ACL='private'
)`,
    awsCliSnippet: (block) => `aws s3api put-bucket-acl --bucket ${block.properties.bucket || block.name} --acl private`,
  },

  // 3. S3 Bucket Server-Side Encryption
  {
    id: 'RULE_S3_ENCRYPTION_DISABLED',
    ruleCode: 'CKV_AWS_19',
    title: 'S3 Bucket Server-Side Encryption (SSE) Not Enforced',
    description: 'Ensure S3 bucket enforces default server-side encryption with AWS KMS or AES256 for data at rest.',
    resourceType: 'aws_s3_bucket',
    severity: 'HIGH',
    cvssScore: 7.7,
    compliance: {
      cis: ['CIS AWS 2.1.1'],
      soc2: ['CC6.1', 'CC6.7'],
      hipaa: ['164.312(a)(2)(iv)', '164.312(e)(2)(ii)'],
      pci: ['PCI-DSS 3.4', 'PCI-DSS 8.2'],
      nist: ['SC-13', 'SC-28'],
    },
    impact: 'Unencrypted storage volumes and objects risk plaintext exposure if physical storage drives or underlying cloud media are compromised.',
    check: (block, allBlocks) => {
      const hasInlineSse = block.rawText.includes('server_side_encryption_configuration');
      const hasSeparateResource = allBlocks.some(
        (b) =>
          b.rawType === 'aws_s3_bucket_server_side_encryption_configuration' &&
          (b.rawText.includes(block.name) || b.rawText.includes(`aws_s3_bucket.${block.name}.id`))
      );
      if (!hasInlineSse && !hasSeparateResource) {
        return { failed: true, message: `Bucket "${block.name}" lacks server-side encryption configuration.` };
      }
      return false;
    },
    remediationAdvice: 'Configure aws_s3_bucket_server_side_encryption_configuration with aws:kms or AES256.',
    remediationSnippet: `resource "aws_s3_bucket_server_side_encryption_configuration" "kms_encryption" {
  bucket = aws_s3_bucket.TARGET_BUCKET.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.primary.arn
    }
  }
}`,
    boto3Snippet: (block) => `import boto3

s3 = boto3.client('s3')
s3.put_bucket_encryption(
    Bucket='${block.properties.bucket || block.name}',
    ServerSideEncryptionConfiguration={
        'Rules': [{
            'ApplyServerSideEncryptionByDefault': {
                'SSEAlgorithm': 'aws:kms'
            }
        }]
    }
)`,
    awsCliSnippet: (block) => `aws s3api put-bucket-encryption --bucket ${block.properties.bucket || block.name} --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'`,
  },

  // 4. IAM Wildcard Action in Policy
  {
    id: 'RULE_IAM_WILDCARD_ACTION',
    ruleCode: 'CKV_AWS_1',
    title: 'IAM Policy Grants Wildcard ("*") Permissions',
    description: 'Ensure IAM policies do not allow unrestricted actions ("*") which violate the principle of least privilege.',
    resourceType: 'aws_iam_policy',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    compliance: {
      cis: ['CIS AWS 1.16', 'CIS AWS 1.22'],
      soc2: ['CC6.1', 'CC6.2', 'CC6.3'],
      hipaa: ['164.312(a)(1)'],
      pci: ['PCI-DSS 7.1', 'PCI-DSS 7.2'],
      nist: ['AC-2', 'AC-3', 'AC-6'],
    },
    impact: 'Wildcard actions allow any compromised credential to execute administrative actions, delete infrastructure, exfiltrate data, or create backdoor accounts.',
    check: (block) => {
      const text = block.rawText;
      // Match Action = ["*"] or "Action": "*" or Action = "*"
      const hasWildcardAction =
        /Action\s*=\s*\[?\s*"\*"\s*\]?/i.test(text) ||
        /"Action"\s*:\s*\[?\s*"\*"\s*\]?/i.test(text) ||
        /Action\s*=\s*"\*"/i.test(text);

      if (hasWildcardAction) {
        return { failed: true, message: 'Policy statement allows unrestricted Action: "*".' };
      }
      return false;
    },
    remediationAdvice: 'Scope down IAM actions to explicitly required API actions (e.g., ["s3:GetObject", "s3:PutObject"]). Avoid "*".',
    remediationSnippet: `    Action = [
      "s3:GetObject",
      "s3:PutObject"
    ]`,
    boto3Snippet: (block) => `# Least privilege policy audit for ${block.name}
import boto3

iam = boto3.client('iam')
# Review and replace policy document with scoped actions
`,
    awsCliSnippet: (block) => `aws iam get-policy-version --policy-arn arn:aws:iam::123456789012:policy/${block.name} --version-id v1`,
  },

  // 5. IAM AdministratorAccess Policy Attachment
  {
    id: 'RULE_IAM_ADMIN_ACCESS_ATTACHED',
    ruleCode: 'CKV_AWS_274',
    title: 'Direct Attachment of AWS Managed AdministratorAccess Policy',
    description: 'Avoid attaching the AdministratorAccess policy directly to IAM roles, users, or groups in production.',
    resourceType: 'aws_iam_role_policy_attachment',
    severity: 'HIGH',
    cvssScore: 8.8,
    compliance: {
      cis: ['CIS AWS 1.16'],
      soc2: ['CC6.2', 'CC6.3'],
      hipaa: ['164.312(a)(1)'],
      pci: ['PCI-DSS 7.1'],
      nist: ['AC-6'],
    },
    impact: 'Grants total root-equivalent permissions across all AWS accounts, bypassing segregation of duties.',
    check: (block) => {
      if (block.rawText.includes('arn:aws:iam::aws:policy/AdministratorAccess')) {
        return { failed: true, message: 'Attaches AdministratorAccess managed policy.' };
      }
      return false;
    },
    remediationAdvice: 'Create a custom IAM policy granting only required services and specific resource ARNs.',
    remediationSnippet: `  policy_arn = aws_iam_policy.custom_scoped_role.arn`,
    boto3Snippet: (block) => `import boto3

iam = boto3.client('iam')
iam.detach_role_policy(
    RoleName='${block.properties.role || 'TARGET_ROLE'}',
    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
)`,
    awsCliSnippet: (block) => `aws iam detach-role-policy --role-name ${block.properties.role || 'TARGET_ROLE'} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`,
  },

  // 6. Security Group Open SSH (0.0.0.0/0 on port 22)
  {
    id: 'RULE_SG_OPEN_SSH',
    ruleCode: 'CKV_AWS_24',
    title: 'Security Group Ingress Allows Unrestricted SSH (Port 22 from 0.0.0.0/0)',
    description: 'Ensure security groups do not allow unrestricted SSH traffic (port 22) from the entire public Internet (0.0.0.0/0).',
    resourceType: 'aws_security_group',
    severity: 'HIGH',
    cvssScore: 8.5,
    compliance: {
      cis: ['CIS AWS 5.2'],
      soc2: ['CC6.6'],
      hipaa: ['164.312(e)(1)'],
      pci: ['PCI-DSS 1.2', 'PCI-DSS 1.3'],
      nist: ['AC-17', 'SC-7'],
    },
    impact: 'Exposes instances to automated credential brute-forcing, zero-day SSH daemon exploits, and botnet port scanning.',
    check: (block) => {
      const text = block.rawText;
      const opensPort22 =
        /from_port\s*=\s*22\b/.test(text) ||
        /to_port\s*=\s*22\b/.test(text) ||
        /port\s*=\s*22\b/.test(text);

      const hasPublicCidr =
        text.includes('"0.0.0.0/0"') ||
        text.includes("'0.0.0.0/0'") ||
        text.includes('"::/0"');

      if (opensPort22 && hasPublicCidr) {
        return { failed: true, message: 'Port 22 (SSH) exposed to 0.0.0.0/0.' };
      }
      return false;
    },
    remediationAdvice: 'Restrict SSH ingress to specific bastion host IPs or private corporate CIDR blocks, or migrate to AWS Systems Manager (SSM) Session Manager.',
    remediationSnippet: `  ingress {
    description = "Bastion Host Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"] # Restrict to private subnet / corporate VPN
  }`,
    boto3Snippet: (block) => `import boto3

ec2 = boto3.client('ec2')
ec2.revoke_security_group_ingress(
    GroupId='${block.properties.id || 'sg-xxxx'}',
    IpPermissions=[{
        'IpProtocol': 'tcp',
        'FromPort': 22,
        'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }]
)`,
    awsCliSnippet: (block) => `aws ec2 revoke-security-group-ingress --group-id ${block.properties.id || 'sg-xxxx'} --protocol tcp --port 22 --cidr 0.0.0.0/0`,
  },

  // 7. Security Group Open Database Ports (5432, 3306, 27017, etc.)
  {
    id: 'RULE_SG_OPEN_DATABASE',
    ruleCode: 'CKV_AWS_23',
    title: 'Security Group Ingress Exposes Database Port to 0.0.0.0/0',
    description: 'Ensure database ports (PostgreSQL 5432, MySQL 3306, MongoDB 27017, MSSQL 1433) are never exposed directly to 0.0.0.0/0.',
    resourceType: 'aws_security_group',
    severity: 'CRITICAL',
    cvssScore: 9.7,
    compliance: {
      cis: ['CIS AWS 5.1', 'CIS AWS 5.3'],
      soc2: ['CC6.1', 'CC6.6'],
      hipaa: ['164.312(a)(1)', '164.312(e)(1)'],
      pci: ['PCI-DSS 1.3', 'PCI-DSS 2.2'],
      nist: ['AC-3', 'SC-7'],
    },
    impact: 'Direct internet connectivity to database instances enables automated ransomware ransom notes, credential stuffing, and data dump breaches.',
    check: (block) => {
      const text = block.rawText;
      const dbPorts = ['5432', '3306', '27017', '1433', '6379'];
      const hasDbPort = dbPorts.some((port) =>
        new RegExp(`(from_port|to_port)\\s*=\\s*${port}\\b`).test(text)
      );
      const hasPublicCidr = text.includes('"0.0.0.0/0"') || text.includes('"::/0"');

      if (hasDbPort && hasPublicCidr) {
        return { failed: true, message: 'Database port ingress exposed to public CIDR 0.0.0.0/0.' };
      }
      return false;
    },
    remediationAdvice: 'Only allow database ingress from application security groups via security_groups attribute or private VPC subnets.',
    remediationSnippet: `  ingress {
    description     = "Database ingress from Web Application tier only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
  }`,
    boto3Snippet: (block) => `import boto3

ec2 = boto3.client('ec2')
ec2.revoke_security_group_ingress(
    GroupId='${block.properties.id || 'sg-xxxx'}',
    IpPermissions=[{
        'IpProtocol': 'tcp',
        'FromPort': 5432,
        'ToPort': 5432,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }]
)`,
    awsCliSnippet: (block) => `aws ec2 revoke-security-group-ingress --group-id ${block.properties.id || 'sg-xxxx'} --protocol tcp --port 5432 --cidr 0.0.0.0/0`,
  },

  // 8. RDS Storage Encryption Disabled
  {
    id: 'RULE_RDS_STORAGE_UNENCRYPTED',
    ruleCode: 'CKV_AWS_16',
    title: 'RDS Database Instance Storage Encryption Disabled',
    description: 'Ensure RDS instances have storage_encrypted enabled with AWS KMS key.',
    resourceType: 'aws_db_instance',
    severity: 'HIGH',
    cvssScore: 8.0,
    compliance: {
      cis: ['CIS AWS 2.3.1'],
      soc2: ['CC6.7'],
      hipaa: ['164.312(a)(2)(iv)'],
      pci: ['PCI-DSS 3.4'],
      nist: ['SC-13', 'SC-28'],
    },
    impact: 'Data stored in RDS tables, automated snapshots, and logs are vulnerable to extraction without cryptographic protection at rest.',
    check: (block) => {
      const encrypted = block.properties['storage_encrypted'];
      if (encrypted === false) {
        return { failed: true, message: 'storage_encrypted explicitly set to false.' };
      }
      if (encrypted === undefined && !block.rawText.includes('storage_encrypted')) {
        return { failed: true, message: 'storage_encrypted attribute missing (defaults to unencrypted on older engines).' };
      }
      return false;
    },
    remediationAdvice: 'Set storage_encrypted = true and supply a dedicated kms_key_id.',
    remediationSnippet: `  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds_key.arn`,
    boto3Snippet: (block) => `import boto3

# Storage encryption cannot be modified on a running instance directly;
# snapshot copy with encryption must be performed.
rds = boto3.client('rds')
snapshot = rds.create_db_snapshot(
    DBSnapshotIdentifier='${block.name}-pre-encrypt',
    DBInstanceIdentifier='${block.properties.identifier || block.name}'
)`,
    awsCliSnippet: (block) => `aws rds create-db-snapshot --db-instance-identifier ${block.properties.identifier || block.name} --db-snapshot-identifier ${block.name}-backup`,
  },

  // 9. RDS Publicly Accessible
  {
    id: 'RULE_RDS_PUBLIC_ACCESSIBLE',
    ruleCode: 'CKV_AWS_17',
    title: 'RDS Database Instance Has Publicly Accessible Endpoint',
    description: 'Ensure RDS database instances are not launched with publicly_accessible = true.',
    resourceType: 'aws_db_instance',
    severity: 'CRITICAL',
    cvssScore: 9.5,
    compliance: {
      cis: ['CIS AWS 2.3.3'],
      soc2: ['CC6.1', 'CC6.6'],
      hipaa: ['164.312(a)(1)'],
      pci: ['PCI-DSS 1.3'],
      nist: ['AC-3', 'SC-7'],
    },
    impact: 'Assigns a publicly resolvable DNS hostname and public IP address to your database server.',
    check: (block) => {
      if (block.properties['publicly_accessible'] === true) {
        return { failed: true, message: 'publicly_accessible set to true.' };
      }
      return false;
    },
    remediationAdvice: 'Set publicly_accessible = false and deploy the database into private isolated VPC subnets.',
    remediationSnippet: `  publicly_accessible = false`,
    boto3Snippet: (block) => `import boto3

rds = boto3.client('rds')
rds.modify_db_instance(
    DBInstanceIdentifier='${block.properties.identifier || block.name}',
    PubliclyAccessible=False,
    ApplyImmediately=True
)`,
    awsCliSnippet: (block) => `aws rds modify-db-instance --db-instance-identifier ${block.properties.identifier || block.name} --no-publicly-accessible --apply-immediately`,
  },

  // 10. EC2 IMDSv1 Allowed (SSRF Token Stealing Risk)
  {
    id: 'RULE_EC2_IMDSV1_ALLOWED',
    ruleCode: 'CKV_AWS_79',
    title: 'EC2 Instance Allows Insecure IMDSv1 (SSRF Credential Theft)',
    description: 'Ensure EC2 instances enforce IMDSv2 (http_tokens = "required") to mitigate Server-Side Request Forgery credential harvesting.',
    resourceType: 'aws_instance',
    severity: 'HIGH',
    cvssScore: 8.6,
    compliance: {
      cis: ['CIS AWS 5.6'],
      soc2: ['CC6.1', 'CC6.6'],
      hipaa: ['164.312(a)(1)'],
      pci: ['PCI-DSS 2.2', 'PCI-DSS 6.5'],
      nist: ['AC-3', 'SC-28'],
    },
    impact: 'SSRF vulnerabilities in web applications allow attackers to retrieve temporary IAM instance profile credentials via http://169.254.169.254 without token header.',
    check: (block) => {
      const text = block.rawText;
      if (!text.includes('metadata_options')) {
        return { failed: true, message: 'metadata_options block missing; IMDSv1 remains permitted by default.' };
      }
      if (text.includes('http_tokens = "optional"')) {
        return { failed: true, message: 'http_tokens set to "optional" instead of "required".' };
      }
      if (!text.includes('http_tokens = "required"')) {
        return { failed: true, message: 'IMDSv2 not enforced.' };
      }
      return false;
    },
    remediationAdvice: 'Add metadata_options with http_tokens = "required" and http_put_response_hop_limit = 1.',
    remediationSnippet: `  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }`,
    boto3Snippet: (block) => `import boto3

ec2 = boto3.client('ec2')
ec2.modify_instance_metadata_options(
    InstanceId='${block.properties.id || 'i-xxxx'}',
    HttpTokens='required',
    HttpPutResponseHopLimit=1
)`,
    awsCliSnippet: (block) => `aws ec2 modify-instance-metadata-options --instance-id ${block.properties.id || 'i-xxxx'} --http-tokens required --http-put-response-hop-limit 1`,
  },

  // 11. CloudTrail Multi-Region & Log Validation Disabled
  {
    id: 'RULE_CLOUDTRAIL_CONFIG',
    ruleCode: 'CKV_AWS_67',
    title: 'CloudTrail Lacks Multi-Region Logging or Log File Validation',
    description: 'Ensure CloudTrail is configured across all regions with log file validation enabled to verify log integrity.',
    resourceType: 'aws_cloudtrail',
    severity: 'HIGH',
    cvssScore: 7.9,
    compliance: {
      cis: ['CIS AWS 3.1', 'CIS AWS 3.2'],
      soc2: ['CC6.8'],
      hipaa: ['164.312(b)'],
      pci: ['PCI-DSS 10.2', 'PCI-DSS 10.5'],
      nist: ['AU-2', 'AU-9', 'AU-12'],
    },
    impact: 'Adversaries operating in unused AWS regions remain invisible. Tampering with audit logs cannot be detected without cryptographic file validation digests.',
    check: (block) => {
      const isMultiRegion = block.properties['is_multi_region_trail'];
      const logValidation = block.properties['enable_log_file_validation'];

      if (isMultiRegion === false || logValidation === false) {
        return { failed: true, message: 'Multi-region or log file validation explicitly disabled.' };
      }
      if (!block.rawText.includes('enable_log_file_validation = true')) {
        return { failed: true, message: 'enable_log_file_validation is not enabled.' };
      }
      if (!block.rawText.includes('is_multi_region_trail = true')) {
        return { failed: true, message: 'is_multi_region_trail is not enabled.' };
      }
      return false;
    },
    remediationAdvice: 'Set is_multi_region_trail = true and enable_log_file_validation = true.',
    remediationSnippet: `  is_multi_region_trail      = true
  enable_log_file_validation = true`,
    boto3Snippet: (block) => `import boto3

trail = boto3.client('cloudtrail')
trail.update_trail(
    Name='${block.properties.name || block.name}',
    IsMultiRegionTrail=True,
    EnableLogFileValidation=True
)`,
    awsCliSnippet: (block) => `aws cloudtrail update-trail --name ${block.properties.name || block.name} --is-multi-region-trail --enable-log-file-validation`,
  },

  // 12. EBS Volume Encryption Disabled
  {
    id: 'RULE_EBS_UNENCRYPTED',
    ruleCode: 'CKV_AWS_3',
    title: 'EBS Volume Data Encryption Disabled',
    description: 'Ensure all EBS volumes have encryption enabled to protect file data and swap partitions at rest.',
    resourceType: 'aws_ebs_volume',
    severity: 'MEDIUM',
    cvssScore: 6.8,
    compliance: {
      cis: ['CIS AWS 2.2.1'],
      soc2: ['CC6.7'],
      hipaa: ['164.312(a)(2)(iv)'],
      pci: ['PCI-DSS 3.4'],
      nist: ['SC-13', 'SC-28'],
    },
    impact: 'Disk snapshots and deleted block storage sectors can be restored and read if not encrypted with AES-256.',
    check: (block) => {
      if (block.properties['encrypted'] === false) {
        return { failed: true, message: 'encrypted = false on EBS volume.' };
      }
      if (!block.rawText.includes('encrypted = true')) {
        return { failed: true, message: 'EBS volume does not enable encryption.' };
      }
      return false;
    },
    remediationAdvice: 'Set encrypted = true and supply kms_key_id.',
    remediationSnippet: `  encrypted  = true
  kms_key_id = aws_kms_key.ebs_key.arn`,
    boto3Snippet: (block) => `import boto3

ec2 = boto3.client('ec2')
ec2.enable_ebs_encryption_by_default()`,
    awsCliSnippet: (block) => `aws ec2 enable-ebs-encryption-by-default`,
  },

  // 13. Hardcoded Secret Keys in Code
  {
    id: 'RULE_HARDCODED_SECRETS',
    ruleCode: 'CKV_SECRET_1',
    title: 'Hardcoded Plaintext AWS Access Key or Secret Detected in IaC',
    description: 'Identify hardcoded credentials such as AKIA... access keys or plaintext secret strings in configuration files.',
    resourceType: 'all',
    severity: 'CRITICAL',
    cvssScore: 9.9,
    compliance: {
      cis: ['CIS AWS 1.4'],
      soc2: ['CC6.1', 'CC6.2'],
      hipaa: ['164.312(d)'],
      pci: ['PCI-DSS 8.2'],
      nist: ['IA-5'],
    },
    impact: 'Hardcoded credentials pushed to git repositories result in automated credential harvesting and immediate cloud account takeover.',
    check: (block) => {
      // Regex for AWS Access Key ID (AKIA...)
      if (/AKIA[0-9A-Z]{16}/.test(block.rawText)) {
        return { failed: true, message: 'Matches AWS Access Key ID pattern (AKIA...).' };
      }
      if (/secret_key\s*=\s*"[^"]{15,}"/.test(block.rawText) || /password\s*=\s*"[^"]{6,}"/.test(block.rawText)) {
        return { failed: true, message: 'Plaintext secret or database password committed in Terraform code.' };
      }
      return false;
    },
    remediationAdvice: 'Remove plaintext credentials immediately. Rotate keys and inject secrets via AWS Secrets Manager or environment variables.',
    remediationSnippet: `  # Reference secrets dynamically:
  password = data.aws_secretsmanager_secret_version.db_pass.secret_string`,
    boto3Snippet: (block) => `# Rotate compromised credentials immediately
import boto3

iam = boto3.client('iam')
# iam.update_access_key(AccessKeyId='AKIA...', Status='Inactive')
`,
    awsCliSnippet: (block) => `aws iam update-access-key --access-key-id AKIAEXAMPLE --status Inactive`,
  },

  // 14. EKS Public Endpoint Access
  {
    id: 'RULE_EKS_PUBLIC_ENDPOINT',
    ruleCode: 'CKV_AWS_39',
    title: 'EKS Kubernetes API Server Public Access Enabled',
    description: 'Ensure EKS cluster API server endpoint is not publicly accessible without CIDR restrictions.',
    resourceType: 'aws_eks_cluster',
    severity: 'HIGH',
    cvssScore: 8.4,
    compliance: {
      cis: ['CIS AWS 5.4'],
      soc2: ['CC6.6'],
      hipaa: ['164.312(e)(1)'],
      pci: ['PCI-DSS 1.3'],
      nist: ['SC-7'],
    },
    impact: 'Exposes Kubernetes control plane API to denial-of-service and credential brute-force attacks from anywhere in the world.',
    check: (block) => {
      const text = block.rawText;
      if (text.includes('endpoint_public_access = true') && !text.includes('public_access_cidrs')) {
        return { failed: true, message: 'EKS API server has public endpoint access without restricting CIDR blocks.' };
      }
      return false;
    },
    remediationAdvice: 'Set endpoint_public_access = false or restrict public_access_cidrs to corporate VPN gateways.',
    remediationSnippet: `  vpc_config {
    endpoint_private_access = true
    endpoint_public_access  = false
  }`,
    boto3Snippet: (block) => `import boto3

eks = boto3.client('eks')
eks.update_cluster_config(
    name='${block.name}',
    resourcesVpcConfig={
        'endpointPublicAccess': False,
        'endpointPrivateAccess': True
    }
)`,
    awsCliSnippet: (block) => `aws eks update-cluster-config --name ${block.name} --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true`,
  },
];
