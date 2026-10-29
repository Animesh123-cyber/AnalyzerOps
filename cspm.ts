export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface ComplianceMapping {
  cis?: string[];
  soc2?: string[];
  hipaa?: string[];
  pci?: string[];
  nist?: string[];
}

export interface Finding {
  id: string;
  ruleCode: string;
  title: string;
  description: string;
  severity: Severity;
  cvssScore: number;
  resourceType: string;
  resourceName: string;
  lineNumber: number;
  endLineNumber?: number;
  snippet?: string;
  compliance: ComplianceMapping;
  impact: string;
  remediationAdvice: string;
  remediationCode: string; // Terraform snippet fix
  boto3Remediation: string; // Python Boto3 script snippet
  awsCliRemediation: string; // AWS CLI command
}

export interface PassedCheck {
  id: string;
  ruleCode: string;
  title: string;
  resourceType: string;
  resourceName: string;
  compliance: ComplianceMapping;
}

export interface ComplianceFrameworkSummary {
  name: string;
  version: string;
  description: string;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  scorePercentage: number;
  controls: {
    id: string;
    title: string;
    status: 'PASS' | 'FAIL';
    severity?: Severity;
    findingIds: string[];
  }[];
}

export interface ScanSummary {
  totalResources: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  passedCount: number;
  postureScore: number; // 0 - 100
  scanDurationMs: number;
  timestamp: string;
  scannedFile: string;
}

export interface ScanResult {
  summary: ScanSummary;
  findings: Finding[];
  passedChecks: PassedCheck[];
  compliance: ComplianceFrameworkSummary[];
  rawSource: string;
}

export interface WebhookConfig {
  url: string;
  platform: 'slack' | 'discord' | 'generic';
  channelName?: string;
  minSeverity: Severity;
  autoAlertOnScan: boolean;
  secretToken?: string;
}

export interface WebhookDispatchRecord {
  id: string;
  timestamp: string;
  targetUrl: string;
  platform: 'slack' | 'discord' | 'generic';
  status: 'SUCCESS' | 'FAILED' | 'SIMULATED';
  statusCode?: number;
  findingsCount: number;
  highestSeverity: Severity;
  payloadPreview: string;
  responseMessage: string;
}

export interface SecurityRuleDefinition {
  id: string;
  ruleCode: string;
  title: string;
  description: string;
  resourceType: string;
  severity: Severity;
  cvssScore: number;
  compliance: ComplianceMapping;
  impact: string;
  check: (block: ResourceBlock, allBlocks: ResourceBlock[]) => { failed: boolean; message?: string; patch?: string } | boolean;
  remediationAdvice: string;
  remediationSnippet: string;
  boto3Snippet: (block: ResourceBlock) => string;
  awsCliSnippet: (block: ResourceBlock) => string;
}

export interface ResourceBlock {
  type: string;
  name: string;
  rawType: string; // e.g. "aws_s3_bucket"
  properties: Record<string, any>;
  rawText: string;
  startLine: number;
  endLine: number;
}
