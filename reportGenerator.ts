import { ScanResult } from '../types/cspm';

export function generateHtmlAuditReport(scanResult: ScanResult): string {
  const { summary, findings, passedChecks, compliance } = scanResult;

  const scoreColor =
    summary.postureScore >= 80 ? '#10b981' : summary.postureScore >= 50 ? '#f59e0b' : '#ef4444';

  const severityBg = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return '#7f1d1d; color: #fecaca; border: 1px solid #ef4444;';
      case 'HIGH':
        return '#7c2d12; color: #ffedd5; border: 1px solid #f97316;';
      case 'MEDIUM':
        return '#713f12; color: #fef08a; border: 1px solid #eab308;';
      default:
        return '#1e293b; color: #cbd5e1; border: 1px solid #475569;';
    }
  };

  const findingsRows = findings
    .map(
      (f, idx) => `
    <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; margin-bottom: 20px; overflow: hidden;">
      <div style="background: #1e293b; padding: 12px 18px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; font-family: monospace; ${severityBg(f.severity)}">
            ${f.severity}
          </span>
          <span style="font-size: 15px; font-weight: 600; color: #f8fafc;">#${idx + 1}. ${f.title}</span>
        </div>
        <div style="font-family: monospace; font-size: 13px; color: #94a3b8;">
          CVSS: <strong style="color: #f1f5f9;">${f.cvssScore}</strong> | Rule: <strong>${f.ruleCode}</strong>
        </div>
      </div>
      <div style="padding: 18px;">
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 14px; font-size: 13px;">
          <div><span style="color: #64748b;">Target Resource:</span> <code style="color: #38bdf8;">${f.resourceType}.${f.resourceName}</code></div>
          <div><span style="color: #64748b;">Line:</span> <span style="color: #f8fafc;">${f.lineNumber}${f.endLineNumber ? ` - ${f.endLineNumber}` : ''}</span></div>
          <div><span style="color: #64748b;">CIS Benchmark:</span> <span style="color: #f8fafc;">${f.compliance.cis?.join(', ') || 'N/A'}</span></div>
          <div><span style="color: #64748b;">SOC 2:</span> <span style="color: #f8fafc;">${f.compliance.soc2?.join(', ') || 'N/A'}</span></div>
        </div>
        <div style="margin-bottom: 12px;">
          <strong style="color: #cbd5e1; font-size: 13px; display: block; margin-bottom: 4px;">Security Impact:</strong>
          <p style="margin: 0; color: #94a3b8; font-size: 13px; line-height: 1.5;">${f.impact}</p>
        </div>
        <div style="margin-bottom: 14px;">
          <strong style="color: #cbd5e1; font-size: 13px; display: block; margin-bottom: 4px;">Remediation Guidance:</strong>
          <p style="margin: 0; color: #94a3b8; font-size: 13px; line-height: 1.5;">${f.remediationAdvice}</p>
        </div>
        <div style="margin-top: 10px;">
          <div style="font-size: 12px; font-weight: 600; color: #38bdf8; margin-bottom: 6px;">Terraform Fix Snippet:</div>
          <pre style="background: #020617; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; color: #34d399; font-family: monospace; font-size: 12px; overflow-x: auto; margin: 0;">${escapeHtml(f.remediationCode)}</pre>
        </div>
        <div style="margin-top: 10px;">
          <div style="font-size: 12px; font-weight: 600; color: #a78bfa; margin-bottom: 6px;">Python Boto3 Remediation:</div>
          <pre style="background: #020617; border: 1px solid #1e293b; padding: 12px; border-radius: 6px; color: #c084fc; font-family: monospace; font-size: 12px; overflow-x: auto; margin: 0;">${escapeHtml(f.boto3Remediation)}</pre>
        </div>
      </div>
    </div>
  `
    )
    .join('');

  const frameworkCards = compliance
    .map(
      (c) => `
    <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 18px; flex: 1; min-width: 220px;">
      <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 8px;">
        <span style="font-weight: 600; color: #f8fafc; font-size: 14px;">${c.name}</span>
        <span style="font-size: 18px; font-weight: 700; color: ${c.scorePercentage >= 80 ? '#10b981' : c.scorePercentage >= 50 ? '#f59e0b' : '#ef4444'};">${c.scorePercentage}%</span>
      </div>
      <div style="background: #1e293b; border-radius: 4px; height: 8px; overflow: hidden; margin-bottom: 8px;">
        <div style="background: ${c.scorePercentage >= 80 ? '#10b981' : c.scorePercentage >= 50 ? '#f59e0b' : '#ef4444'}; width: ${c.scorePercentage}%; height: 100%;"></div>
      </div>
      <div style="font-size: 12px; color: #64748b; display: flex; justify-content: space-between;">
        <span>${c.passedControls} Controls Passed</span>
        <span style="color: #ef4444;">${c.failedControls} Failed</span>
      </div>
    </div>
  `
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CloudGuard CSPM Audit Report - ${summary.scannedFile}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      background-color: #020617;
      color: #f8fafc;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      margin: 0;
      padding: 30px;
      line-height: 1.6;
    }
    @media print {
      body { background: #fff; color: #000; padding: 15px; }
      pre { background: #f4f4f5 !important; color: #18181b !important; border: 1px solid #e4e4e7 !important; }
    }
  </style>
</head>
<body>
  <div style="max-width: 1100px; margin: 0 auto;">
    <!-- Header -->
    <div style="border-bottom: 1px solid #1e293b; padding-bottom: 24px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
      <div>
        <h1 style="font-size: 26px; margin: 0 0 6px 0; color: #f8fafc; display: flex; align-items: center; gap: 10px;">
          🛡️ CloudGuard CSPM Security Report
        </h1>
        <p style="margin: 0; color: #64748b; font-size: 14px;">
          DevSecOps Posture & Compliance Automator • Scanned: <span style="color: #cbd5e1;">${summary.scannedFile}</span>
        </p>
      </div>
      <div style="text-align: right; font-size: 12px; color: #64748b;">
        <div>Timestamp: <span style="color: #cbd5e1;">${new Date(summary.timestamp).toUTCString()}</span></div>
        <div>Scan Duration: <span style="color: #cbd5e1;">${summary.scanDurationMs}ms</span></div>
      </div>
    </div>

    <!-- Executive Summary Card -->
    <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 10px; padding: 24px; margin-bottom: 30px; display: flex; flex-wrap: wrap; gap: 24px; align-items: center;">
      <div style="text-align: center; padding: 10px 24px; border-right: 1px solid #1e293b;">
        <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 4px;">Posture Score</div>
        <div style="font-size: 48px; font-weight: 800; color: ${scoreColor}; font-family: monospace;">${summary.postureScore}<span style="font-size: 20px; color: #64748b;">/100</span></div>
      </div>
      <div style="display: flex; gap: 20px; flex-wrap: wrap; flex: 1;">
        <div>
          <div style="font-size: 12px; color: #64748b;">Total Findings</div>
          <div style="font-size: 24px; font-weight: 700; color: #f8fafc;">${summary.totalFindings}</div>
        </div>
        <div>
          <div style="font-size: 12px; color: #ef4444;">Critical</div>
          <div style="font-size: 24px; font-weight: 700; color: #ef4444;">${summary.criticalCount}</div>
        </div>
        <div>
          <div style="font-size: 12px; color: #f97316;">High</div>
          <div style="font-size: 24px; font-weight: 700; color: #f97316;">${summary.highCount}</div>
        </div>
        <div>
          <div style="font-size: 12px; color: #eab308;">Medium</div>
          <div style="font-size: 24px; font-weight: 700; color: #eab308;">${summary.mediumCount}</div>
        </div>
        <div>
          <div style="font-size: 12px; color: #10b981;">Passed Checks</div>
          <div style="font-size: 24px; font-weight: 700; color: #10b981;">${summary.passedCount}</div>
        </div>
        <div>
          <div style="font-size: 12px; color: #64748b;">Resources Audited</div>
          <div style="font-size: 24px; font-weight: 700; color: #38bdf8;">${summary.totalResources}</div>
        </div>
      </div>
    </div>

    <!-- Framework Scorecards -->
    <h2 style="font-size: 18px; margin: 0 0 16px 0; color: #f8fafc;">Compliance Framework Scorecards</h2>
    <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 36px;">
      ${frameworkCards}
    </div>

    <!-- Detailed Findings -->
    <h2 style="font-size: 18px; margin: 0 0 16px 0; color: #f8fafc;">
      Vulnerability & Misconfiguration Findings (${findings.length})
    </h2>
    ${findings.length === 0 ? '<div style="background: #0f172a; padding: 24px; border-radius: 8px; text-align: center; color: #10b981;">No security misconfigurations detected. Infrastructure passed all CSPM policies!</div>' : findingsRows}

    <!-- Footer -->
    <div style="border-top: 1px solid #1e293b; padding-top: 20px; margin-top: 40px; text-align: center; font-size: 12px; color: #64748b;">
      Report generated by CloudGuard CSPM • Automated Cloud Security & Compliance Engine
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
