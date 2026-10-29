import {
  Finding,
  PassedCheck,
  ComplianceFrameworkSummary,
  ScanSummary,
  ScanResult,
  ResourceBlock,
} from '../types/cspm';
import { parseTerraformHcl } from './iacParser';
import { CSPM_RULES } from './cspmRules';

interface FrameworkDefinition {
  name: string;
  version: string;
  description: string;
  controls: { id: string; title: string; category: string }[];
}

export const FRAMEWORKS: FrameworkDefinition[] = [
  {
    name: 'CIS AWS Foundations Benchmark',
    version: 'v3.0.0',
    description: 'Industry-standard technical guidelines for securing AWS environments.',
    controls: [
      { id: 'CIS AWS 1.16', title: 'Ensure IAM policies do not allow unrestricted administrative privileges', category: 'Identity and Access Management' },
      { id: 'CIS AWS 1.22', title: 'Ensure IAM actions adhere to least privilege principle', category: 'Identity and Access Management' },
      { id: 'CIS AWS 2.1.1', title: 'Ensure S3 Buckets are encrypted with Customer Managed Keys or KMS', category: 'Storage' },
      { id: 'CIS AWS 2.1.5', title: 'Ensure S3 Bucket Access is blocked from public internet', category: 'Storage' },
      { id: 'CIS AWS 2.2.1', title: 'Ensure EBS volume encryption is enabled', category: 'Storage' },
      { id: 'CIS AWS 2.3.1', title: 'Ensure RDS storage encryption is enabled', category: 'Database' },
      { id: 'CIS AWS 2.3.3', title: 'Ensure RDS instances are not publicly accessible', category: 'Database' },
      { id: 'CIS AWS 3.1', title: 'Ensure CloudTrail is enabled across all regions', category: 'Logging & Monitoring' },
      { id: 'CIS AWS 3.2', title: 'Ensure CloudTrail log file validation is enabled', category: 'Logging & Monitoring' },
      { id: 'CIS AWS 5.1', title: 'Ensure no Security Groups allow ingress from 0.0.0.0/0 to port 22', category: 'Networking' },
      { id: 'CIS AWS 5.2', title: 'Ensure no Security Groups allow ingress from 0.0.0.0/0 to port 3389', category: 'Networking' },
      { id: 'CIS AWS 5.3', title: 'Ensure no Security Groups allow ingress from 0.0.0.0/0 to database ports', category: 'Networking' },
      { id: 'CIS AWS 5.6', title: 'Ensure EC2 instances enforce IMDSv2 metadata tokens', category: 'Compute' },
    ],
  },
  {
    name: 'SOC 2 Type II',
    version: 'Trust Services Criteria 2022',
    description: 'Security, Confidentiality, and Processing Integrity compliance for cloud platforms.',
    controls: [
      { id: 'CC6.1', title: 'Logical Access Controls & Network Boundary Protections', category: 'Logical Access' },
      { id: 'CC6.2', title: 'User Registration & Least Privilege Role Assignment', category: 'Logical Access' },
      { id: 'CC6.3', title: 'Revocation of Access & Privilege Management', category: 'Logical Access' },
      { id: 'CC6.6', title: 'Protection Against External Threat Actors & Boundary Defense', category: 'System Operations' },
      { id: 'CC6.7', title: 'Encryption of Sensitive Data at Rest and in Transit', category: 'Data Protection' },
      { id: 'CC6.8', title: 'Tamper-Resistant Security Logging & Audit Trails', category: 'Monitoring' },
    ],
  },
  {
    name: 'HIPAA Security Rule',
    version: '45 CFR Part 164 Subpart C',
    description: 'Standards for the Protection of Electronic Protected Health Information (ePHI).',
    controls: [
      { id: '164.312(a)(1)', title: 'Access Control - Unique User Identification & Emergency Access', category: 'Technical Safeguards' },
      { id: '164.312(a)(2)(iv)', title: 'Encryption and Decryption of ePHI at Rest', category: 'Technical Safeguards' },
      { id: '164.312(b)', title: 'Audit Controls - Recording and Examination of Activity', category: 'Technical Safeguards' },
      { id: '164.312(c)(1)', title: 'Integrity Controls - Corroboration of ePHI Non-Alteration', category: 'Technical Safeguards' },
      { id: '164.312(e)(1)', title: 'Transmission Security - Guard Against Unauthorized Access in Transit', category: 'Technical Safeguards' },
    ],
  },
  {
    name: 'PCI-DSS',
    version: 'v4.0.1',
    description: 'Payment Card Industry Data Security Standard for protecting cardholder data.',
    controls: [
      { id: 'PCI-DSS 1.2', title: 'Network Security Controls are configured and maintained', category: 'Network Security' },
      { id: 'PCI-DSS 1.3', title: 'Network access to and from cardholder data environment is restricted', category: 'Network Security' },
      { id: 'PCI-DSS 2.2', title: 'System components are configured securely with industry standards', category: 'Secure Configuration' },
      { id: 'PCI-DSS 3.4', title: 'Primary Account Numbers (PAN) are rendered unreadable anywhere stored', category: 'Data Protection' },
      { id: 'PCI-DSS 7.1', title: 'Access to system components and data is limited by business need', category: 'Access Control' },
      { id: 'PCI-DSS 8.2', title: 'User identity management and strong authentication', category: 'Access Control' },
      { id: 'PCI-DSS 10.2', title: 'Audit logs are implemented to record all user access', category: 'Logging & Monitoring' },
    ],
  },
];

export function runCspmScan(
  sourceCode: string,
  filename: string = 'main.tf'
): ScanResult {
  const startTime = Date.now();
  const blocks = parseTerraformHcl(sourceCode);
  const findings: Finding[] = [];
  const passedChecks: PassedCheck[] = [];

  for (const rule of CSPM_RULES) {
    // Find matching blocks for this rule
    const matchingBlocks =
      rule.resourceType === 'all'
        ? blocks
        : blocks.filter((b) => b.rawType === rule.resourceType);

    if (matchingBlocks.length === 0) {
      continue;
    }

    for (const block of matchingBlocks) {
      const checkResult = rule.check(block, blocks);
      const isFailed = typeof checkResult === 'boolean' ? checkResult : checkResult.failed;

      if (isFailed) {
        const failureMsg = typeof checkResult === 'object' && checkResult.message ? checkResult.message : rule.description;
        const lineSnippet = block.rawText.split('\n').slice(0, 10).join('\n');

        findings.push({
          id: `${rule.ruleCode}_${block.name}_${block.startLine}`,
          ruleCode: rule.ruleCode,
          title: rule.title,
          description: `${rule.description} (${failureMsg})`,
          severity: rule.severity,
          cvssScore: rule.cvssScore,
          resourceType: block.rawType,
          resourceName: block.name,
          lineNumber: block.startLine,
          endLineNumber: block.endLine,
          snippet: lineSnippet,
          compliance: rule.compliance,
          impact: rule.impact,
          remediationAdvice: rule.remediationAdvice,
          remediationCode: rule.remediationSnippet.replace(/TARGET_BUCKET/g, block.name),
          boto3Remediation: rule.boto3Snippet(block),
          awsCliRemediation: rule.awsCliSnippet(block),
        });
      } else {
        passedChecks.push({
          id: `${rule.ruleCode}_${block.name}_PASS`,
          ruleCode: rule.ruleCode,
          title: rule.title,
          resourceType: block.rawType,
          resourceName: block.name,
          compliance: rule.compliance,
        });
      }
    }
  }

  // Count severities
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const f of findings) {
    if (f.severity === 'CRITICAL') criticalCount++;
    else if (f.severity === 'HIGH') highCount++;
    else if (f.severity === 'MEDIUM') mediumCount++;
    else lowCount++;
  }

  // Calculate Security Posture Score (0 - 100)
  // Base 100, deducted by severity penalty with minimum 0
  const penalty = criticalCount * 25 + highCount * 12 + mediumCount * 5 + lowCount * 2;
  const postureScore = Math.max(0, Math.min(100, Math.round(100 - penalty)));

  // Calculate compliance frameworks summaries
  const complianceSummaries: ComplianceFrameworkSummary[] = FRAMEWORKS.map((fw) => {
    let passed = 0;
    let failed = 0;

    const controls = fw.controls.map((ctrl) => {
      // Check if any finding failed this control
      const matchingFindings = findings.filter((f) => {
        const cisMatches = f.compliance.cis?.some((c) => c.startsWith(ctrl.id));
        const soc2Matches = f.compliance.soc2?.includes(ctrl.id);
        const hipaaMatches = f.compliance.hipaa?.some((h) => h.startsWith(ctrl.id));
        const pciMatches = f.compliance.pci?.some((p) => p.startsWith(ctrl.id));
        return cisMatches || soc2Matches || hipaaMatches || pciMatches;
      });

      if (matchingFindings.length > 0) {
        failed++;
        return {
          id: ctrl.id,
          title: ctrl.title,
          status: 'FAIL' as const,
          severity: matchingFindings[0].severity,
          findingIds: matchingFindings.map((f) => f.id),
        };
      } else {
        passed++;
        return {
          id: ctrl.id,
          title: ctrl.title,
          status: 'PASS' as const,
          findingIds: [],
        };
      }
    });

    const total = controls.length;
    const scorePercentage = total > 0 ? Math.round((passed / total) * 100) : 100;

    return {
      name: fw.name,
      version: fw.version,
      description: fw.description,
      totalControls: total,
      passedControls: passed,
      failedControls: failed,
      scorePercentage,
      controls,
    };
  });

  const duration = Date.now() - startTime;

  const summary: ScanSummary = {
    totalResources: blocks.length,
    totalFindings: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    passedCount: passedChecks.length,
    postureScore,
    scanDurationMs: duration,
    timestamp: new Date().toISOString(),
    scannedFile: filename,
  };

  return {
    summary,
    findings,
    passedChecks,
    compliance: complianceSummaries,
    rawSource: sourceCode,
  };
}
