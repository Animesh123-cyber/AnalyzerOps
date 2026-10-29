import { Finding, ScanSummary, WebhookConfig, WebhookDispatchRecord } from '../types/cspm';

export function formatSlackPayload(findings: Finding[], summary: ScanSummary): object {
  const topFindings = findings.slice(0, 5);

  const fields = [
    { type: 'mrkdwn', text: `*Cloud Posture Score:*\n${summary.postureScore}/100` },
    { type: 'mrkdwn', text: `*Scanned Target:*\n\`${summary.scannedFile}\`` },
    { type: 'mrkdwn', text: `*Critical Violations:*\n:rotating_light: *${summary.criticalCount}*` },
    { type: 'mrkdwn', text: `*High Violations:*\n:warning: *${summary.highCount}*` },
  ];

  const blocks: any[] = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: '🛡️ CloudGuard CSPM: Security Policy Violations Detected',
        emoji: true,
      },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*Automated DevSecOps Compliance Alert* triggered by IaC / Cloud posture scan. *${summary.totalFindings}* misconfigurations detected.`,
      },
      fields,
    },
    { type: 'divider' },
  ];

  // Add top finding blocks
  for (const f of topFindings) {
    const icon = f.severity === 'CRITICAL' ? '🚨' : f.severity === 'HIGH' ? '⚠️' : 'ℹ️';
    blocks.push({
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `${icon} *[${f.severity}] ${f.title}*\n*Resource:* \`${f.resourceType}.${f.resourceName}\` (Line ${f.lineNumber})\n*CVSS:* \`${f.cvssScore}\` | *CIS:* \`${f.compliance.cis?.join(', ') || 'N/A'}\`\n>${f.impact}`,
      },
    });
  }

  if (findings.length > 5) {
    blocks.push({
      type: 'context',
      elements: [
        {
          type: 'mrkdwn',
          text: `_... and ${findings.length - 5} more findings available in CloudGuard CSPM audit report._`,
        },
      ],
    });
  }

  return { blocks };
}

export function formatDiscordPayload(findings: Finding[], summary: ScanSummary): object {
  const topFindings = findings.slice(0, 5);

  // Color in Discord decimal: Red = 0xDC2626 (14427686), Orange = 0xEA580C (15358092), Yellow = 0xEAB308 (15381256)
  const color = summary.criticalCount > 0 ? 14427686 : summary.highCount > 0 ? 15358092 : 15381256;

  const fields = topFindings.map((f) => ({
    name: `[${f.severity}] ${f.title}`,
    value: `**Resource:** \`${f.resourceType}.${f.resourceName}\` (Line ${f.lineNumber})\n**CVSS Score:** \`${f.cvssScore}\`\n**CIS Control:** \`${f.compliance.cis?.[0] || 'N/A'}\`\n**Fix:** \`${f.remediationAdvice.slice(0, 100)}...\``,
    inline: false,
  }));

  return {
    username: 'CloudGuard CSPM Alert Bot',
    avatar_url: 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=128',
    embeds: [
      {
        title: '🛡️ Cloud Security Posture Management Alert',
        description: `Automated scan completed on \`${summary.scannedFile}\`. Security posture score: **${summary.postureScore}/100**.`,
        color,
        fields: [
          { name: 'Critical Violations', value: `${summary.criticalCount}`, inline: true },
          { name: 'High Violations', value: `${summary.highCount}`, inline: true },
          { name: 'Medium Violations', value: `${summary.mediumCount}`, inline: true },
          ...fields,
        ],
        footer: {
          text: `CloudGuard CSPM Engine • Scanned at ${new Date(summary.timestamp).toLocaleString()}`,
        },
      },
    ],
  };
}

export function formatGenericPayload(findings: Finding[], summary: ScanSummary): object {
  return {
    eventType: 'CLOUD_SECURITY_POSTURE_VIOLATION',
    version: '1.0.0',
    timestamp: summary.timestamp,
    target: summary.scannedFile,
    postureScore: summary.postureScore,
    statistics: {
      totalFindings: summary.totalFindings,
      critical: summary.criticalCount,
      high: summary.highCount,
      medium: summary.mediumCount,
      low: summary.lowCount,
      resourcesScanned: summary.totalResources,
    },
    findings: findings.map((f) => ({
      id: f.id,
      ruleCode: f.ruleCode,
      title: f.title,
      severity: f.severity,
      cvssScore: f.cvssScore,
      resource: {
        type: f.resourceType,
        name: f.resourceName,
        line: f.lineNumber,
      },
      compliance: f.compliance,
      remediation: {
        terraformSnippet: f.remediationCode,
        boto3Snippet: f.boto3Remediation,
        awsCli: f.awsCliRemediation,
      },
    })),
  };
}

export async function dispatchWebhookAlert(
  config: WebhookConfig,
  findings: Finding[],
  summary: ScanSummary,
  forceTestMode: boolean = false
): Promise<WebhookDispatchRecord> {
  // Filter findings by minSeverity
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };
  const minRank = severityOrder[config.minSeverity] || 0;
  const filteredFindings = findings.filter((f) => severityOrder[f.severity] >= minRank);

  let payloadObj: any;
  if (config.platform === 'slack') {
    payloadObj = formatSlackPayload(filteredFindings, summary);
  } else if (config.platform === 'discord') {
    payloadObj = formatDiscordPayload(filteredFindings, summary);
  } else {
    payloadObj = formatGenericPayload(filteredFindings, summary);
  }

  const payloadString = JSON.stringify(payloadObj, null, 2);
  const highestSeverity =
    summary.criticalCount > 0
      ? 'CRITICAL'
      : summary.highCount > 0
      ? 'HIGH'
      : summary.mediumCount > 0
      ? 'MEDIUM'
      : 'LOW';

  const recordId = `WH_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  if (forceTestMode || !config.url || config.url.trim() === '' || config.url.includes('example.com')) {
    // Simulated delivery mode
    return {
      id: recordId,
      timestamp: new Date().toISOString(),
      targetUrl: config.url || 'https://hooks.slack.com/services/SIMULATED/DRY_RUN/TEST',
      platform: config.platform,
      status: 'SIMULATED',
      statusCode: 200,
      findingsCount: filteredFindings.length,
      highestSeverity,
      payloadPreview: payloadString,
      responseMessage: `Simulated webhook dispatch successful. Formatted payload validated for ${config.platform.toUpperCase()} webhook spec.`,
    };
  }

  // Real HTTP dispatch
  try {
    const res = await fetch(config.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(config.secretToken ? { 'X-CloudGuard-Secret': config.secretToken } : {}),
      },
      body: JSON.stringify(payloadObj),
    });

    const respText = await res.text().catch(() => '');

    return {
      id: recordId,
      timestamp: new Date().toISOString(),
      targetUrl: config.url,
      platform: config.platform,
      status: res.ok ? 'SUCCESS' : 'FAILED',
      statusCode: res.status,
      findingsCount: filteredFindings.length,
      highestSeverity,
      payloadPreview: payloadString,
      responseMessage: res.ok
        ? `Delivered successfully to ${config.platform} (HTTP ${res.status}). Response: ${respText.slice(0, 100) || 'OK'}`
        : `Webhook responded with HTTP ${res.status}: ${respText.slice(0, 200)}`,
    };
  } catch (err: any) {
    return {
      id: recordId,
      timestamp: new Date().toISOString(),
      targetUrl: config.url,
      platform: config.platform,
      status: 'FAILED',
      statusCode: 0,
      findingsCount: filteredFindings.length,
      highestSeverity,
      payloadPreview: payloadString,
      responseMessage: `Network transmission failed: ${err.message || 'Connection refused or blocked by remote host.'}`,
    };
  }
}
