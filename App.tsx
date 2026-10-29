import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { DashboardView } from './components/DashboardView';
import { DataVerifierView } from './components/DataVerifierView';
import { IacScannerView } from './components/IacScannerView';
import { ComplianceView } from './components/ComplianceView';
import { WebhookView } from './components/WebhookView';
import { RemediationView } from './components/RemediationView';
import { ExportModal } from './components/ExportModal';
import { runCspmScan } from './lib/complianceEngine';
import { SAMPLE_TEMPLATES } from './lib/sampleTemplates';
import { Finding, ScanResult, WebhookConfig, WebhookDispatchRecord } from './types/cspm';
import { dispatchWebhookAlert } from './lib/webhookDispatcher';
import { CheckCircle2 } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'verifier' | 'scanner' | 'compliance' | 'webhooks' | 'remediation'>('dashboard');
  const [sourceCode, setSourceCode] = useState<string>(SAMPLE_TEMPLATES[0].code);
  const [fileName, setFileName] = useState<string>('vulnerable-startup.tf');
  const [scanResult, setScanResult] = useState<ScanResult>(() =>
    runCspmScan(SAMPLE_TEMPLATES[0].code, 'vulnerable-startup.tf')
  );
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [remediationToast, setRemediationToast] = useState<string | null>(null);

  // Webhook State
  const [webhookConfig, setWebhookConfig] = useState<WebhookConfig>({
    url: '',
    platform: 'slack',
    minSeverity: 'HIGH',
    autoAlertOnScan: false,
  });
  const [dispatchHistory, setDispatchHistory] = useState<WebhookDispatchRecord[]>([]);
  const [isDispatching, setIsDispatching] = useState(false);

  // Run scan handler
  const handleRunScan = (codeToScan?: string) => {
    const targetCode = typeof codeToScan === 'string' ? codeToScan : sourceCode;
    const newResult = runCspmScan(targetCode, fileName);
    setScanResult(newResult);
    if (selectedFinding) {
      // Keep selected finding if still present
      const stillExists = newResult.findings.find((f) => f.id === selectedFinding.id);
      setSelectedFinding(stillExists || null);
    }
  };

  // Load verified code into full IaC scanner
  const handleLoadIntoScanner = (code: string, newFileName: string) => {
    setSourceCode(code);
    setFileName(newFileName);
    const newResult = runCspmScan(code, newFileName);
    setScanResult(newResult);
    setActiveTab('scanner');
    setRemediationToast(`Loaded verified configuration "${newFileName}" into IaC Scanner.`);
    setTimeout(() => setRemediationToast(null), 3500);
  };

  // 1-Click Auto Remediation implementation
  const handleApplyRemediation = (finding: Finding) => {
    let updatedCode = sourceCode;

    // Intelligent patch replacements
    if (finding.ruleCode === 'CKV_AWS_20') {
      // Public ACL -> private
      updatedCode = updatedCode.replace(/acl\s*=\s*"public-read[^"]*"/g, 'acl    = "private"');
    } else if (finding.ruleCode === 'CKV_AWS_1') {
      // IAM wildcard Action -> scoped actions
      updatedCode = updatedCode.replace(
        /Action\s*=\s*"\*"/g,
        'Action = [\n          "s3:GetObject",\n          "s3:PutObject"\n        ]'
      );
    } else if (finding.ruleCode === 'CKV_AWS_274') {
      // AdministratorAccess detachment
      updatedCode = updatedCode.replace(
        /arn:aws:iam::aws:policy\/AdministratorAccess/g,
        'arn:aws:iam::aws:policy/ReadOnlyAccess'
      );
    } else if (finding.ruleCode === 'CKV_AWS_24' || finding.ruleCode === 'CKV_AWS_23') {
      // Security Group open CIDR
      updatedCode = updatedCode.replace(
        /cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\]/g,
        'cidr_blocks = ["10.0.1.0/24"] # Restriced to corporate VPN'
      );
    } else if (finding.ruleCode === 'CKV_AWS_16') {
      // RDS storage_encrypted false -> true
      updatedCode = updatedCode.replace(
        /storage_encrypted\s*=\s*false/g,
        'storage_encrypted   = true'
      );
    } else if (finding.ruleCode === 'CKV_AWS_17') {
      // RDS publicly_accessible true -> false
      updatedCode = updatedCode.replace(
        /publicly_accessible\s*=\s*true/g,
        'publicly_accessible = false'
      );
    } else if (finding.ruleCode === 'CKV_AWS_79') {
      // EC2 IMDSv2 enforcement
      updatedCode = updatedCode.replace(
        /resource "aws_instance" "([^"]+)" \{/g,
        `resource "aws_instance" "$1" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }`
      );
    } else if (finding.ruleCode === 'CKV_AWS_3') {
      // EBS encrypted false -> true
      updatedCode = updatedCode.replace(
        /encrypted\s*=\s*false/g,
        'encrypted         = true'
      );
    } else if (finding.ruleCode === 'CKV_AWS_53') {
      // S3 Public Access Block addition
      const s3Block = `
resource "aws_s3_bucket_public_access_block" "${finding.resourceName}_access_block" {
  bucket = aws_s3_bucket.${finding.resourceName}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
`;
      updatedCode = updatedCode + s3Block;
    } else if (finding.ruleCode === 'CKV_SECRET_1') {
      // Hardcoded secret replacement
      updatedCode = updatedCode.replace(
        /password\s*=\s*"[^"]+"/g,
        'password = var.db_password # Injected via AWS Secrets Manager'
      );
    }

    setSourceCode(updatedCode);
    const newResult = runCspmScan(updatedCode, fileName);
    setScanResult(newResult);
    setSelectedFinding(null);

    setRemediationToast(`Auto-remediated ${finding.ruleCode} (${finding.resourceName}). Security score improved!`);
    setTimeout(() => setRemediationToast(null), 4000);
  };

  // Dispatch Webhook handler
  const handleDispatchWebhook = async (forceTest: boolean) => {
    setIsDispatching(true);
    try {
      // Attempt backend API call first
      const res = await fetch('/api/webhook/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          webhookConfig,
          findings: scanResult.findings,
          summary: scanResult.summary,
          forceTestMode: forceTest,
        }),
      });

      if (res.ok) {
        const record: WebhookDispatchRecord = await res.json();
        setDispatchHistory((prev) => [record, ...prev]);
      } else {
        // Fallback to client-side dispatcher
        const record = await dispatchWebhookAlert(
          webhookConfig,
          scanResult.findings,
          scanResult.summary,
          forceTest
        );
        setDispatchHistory((prev) => [record, ...prev]);
      }
    } catch {
      // Fallback to client-side dispatcher if backend call failed
      const record = await dispatchWebhookAlert(
        webhookConfig,
        scanResult.findings,
        scanResult.summary,
        forceTest
      );
      setDispatchHistory((prev) => [record, ...prev]);
    } finally {
      setIsDispatching(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Strict 3-Zone Top Bar Contract */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onExportClick={() => setIsExportModalOpen(true)}
      />

      {/* Toast Notification */}
      {remediationToast && (
        <div className="fixed bottom-6 right-6 z-50 bg-emerald-950 border border-emerald-600 text-emerald-200 px-4 py-2.5 rounded-lg shadow-xl flex items-center gap-2 text-xs font-medium animate-in fade-in slide-in-from-bottom-3">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{remediationToast}</span>
        </div>
      )}

      {/* Main Viewport Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'dashboard' && (
          <DashboardView
            scanResult={scanResult}
            onSelectFinding={(f) => {
              setSelectedFinding(f);
              setActiveTab('scanner');
            }}
            onNavigateToScanner={() => setActiveTab('scanner')}
            onNavigateToVerifier={() => setActiveTab('verifier')}
            onNavigateToCompliance={() => setActiveTab('compliance')}
            onNavigateToWebhooks={() => setActiveTab('webhooks')}
          />
        )}

        {activeTab === 'verifier' && (
          <DataVerifierView
            onLoadIntoScanner={handleLoadIntoScanner}
          />
        )}

        {activeTab === 'scanner' && (
          <IacScannerView
            sourceCode={sourceCode}
            setSourceCode={setSourceCode}
            fileName={fileName}
            setFileName={setFileName}
            scanResult={scanResult}
            onRunScan={handleRunScan}
            selectedFinding={selectedFinding}
            setSelectedFinding={setSelectedFinding}
            onApplyRemediation={handleApplyRemediation}
          />
        )}

        {activeTab === 'compliance' && (
          <ComplianceView
            scanResult={scanResult}
            onSelectFinding={(f) => {
              setSelectedFinding(f);
              setActiveTab('scanner');
            }}
            onNavigateToScanner={() => setActiveTab('scanner')}
          />
        )}

        {activeTab === 'webhooks' && (
          <WebhookView
            scanResult={scanResult}
            webhookConfig={webhookConfig}
            setWebhookConfig={setWebhookConfig}
            dispatchHistory={dispatchHistory}
            onDispatchWebhook={handleDispatchWebhook}
            isDispatching={isDispatching}
          />
        )}

        {activeTab === 'remediation' && (
          <RemediationView
            scanResult={scanResult}
            onApplyRemediation={handleApplyRemediation}
            onNavigateToScanner={() => setActiveTab('scanner')}
          />
        )}
      </main>

      {/* Export Report Modal */}
      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        scanResult={scanResult}
      />
    </div>
  );
}
