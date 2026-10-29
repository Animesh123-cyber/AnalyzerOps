import { ResourceBlock } from '../types/cspm';

/**
 * Robust HCL / Terraform parser that parses resources, attributes, and tracks line numbers
 */
export function parseTerraformHcl(sourceCode: string): ResourceBlock[] {
  const blocks: ResourceBlock[] = [];
  const lines = sourceCode.split('\n');

  // Regex to match: resource "type" "name" {
  const resourceHeaderRegex = /^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{?/;
  const moduleHeaderRegex = /^\s*module\s+"([^"]+)"\s*\{?/;

  let currentBlock: {
    type: string;
    name: string;
    startLine: number;
    lines: string[];
    braceCount: number;
  } | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;

    // Check if we are outside a block and encounter a resource header
    if (!currentBlock) {
      const match = line.match(resourceHeaderRegex);
      if (match) {
        const type = match[1];
        const name = match[2];
        const openBraces = (line.match(/\{/g) || []).length;
        const closeBraces = (line.match(/\}/g) || []).length;

        currentBlock = {
          type,
          name,
          startLine: lineNumber,
          lines: [line],
          braceCount: openBraces - closeBraces,
        };

        if (currentBlock.braceCount === 0 && openBraces > 0) {
          // One-liner block
          blocks.push(buildResourceBlock(currentBlock, lineNumber));
          currentBlock = null;
        }
        continue;
      }

      const modMatch = line.match(moduleHeaderRegex);
      if (modMatch) {
        const name = modMatch[1];
        const openBraces = (line.match(/\{/g) || []).length;
        const closeBraces = (line.match(/\}/g) || []).length;
        currentBlock = {
          type: 'module',
          name,
          startLine: lineNumber,
          lines: [line],
          braceCount: openBraces - closeBraces,
        };
        if (currentBlock.braceCount === 0 && openBraces > 0) {
          blocks.push(buildResourceBlock(currentBlock, lineNumber));
          currentBlock = null;
        }
        continue;
      }
    } else {
      // Inside an active block
      currentBlock.lines.push(line);
      const openBraces = (line.match(/\{/g) || []).length;
      const closeBraces = (line.match(/\}/g) || []).length;
      currentBlock.braceCount += openBraces - closeBraces;

      if (currentBlock.braceCount <= 0) {
        // Block closed
        blocks.push(buildResourceBlock(currentBlock, lineNumber));
        currentBlock = null;
      }
    }
  }

  return blocks;
}

function buildResourceBlock(
  blockInfo: { type: string; name: string; startLine: number; lines: string[] },
  endLine: number
): ResourceBlock {
  const rawText = blockInfo.lines.join('\n');
  const properties = parseBlockProperties(blockInfo.lines);

  return {
    type: blockInfo.type,
    name: blockInfo.name,
    rawType: blockInfo.type,
    properties,
    rawText,
    startLine: blockInfo.startLine,
    endLine,
  };
}

/**
 * Extracts basic key/value pairs and detects patterns in the block lines
 */
function parseBlockProperties(lines: string[]): Record<string, any> {
  const props: Record<string, any> = {};
  const fullText = lines.join('\n');

  // Simple key = value extractor
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) continue;

    const kvMatch = trimmed.match(/^([a-zA-Z0-9_\-]+)\s*=\s*(.*)$/);
    if (kvMatch) {
      const key = kvMatch[1];
      let valStr = kvMatch[2].trim();

      // Clean trailing commas or comments
      valStr = valStr.replace(/#.*$/, '').replace(/\/\/.*$/, '').trim();

      if (valStr.startsWith('"') && valStr.endsWith('"')) {
        props[key] = valStr.slice(1, -1);
      } else if (valStr === 'true') {
        props[key] = true;
      } else if (valStr === 'false') {
        props[key] = false;
      } else if (!isNaN(Number(valStr)) && valStr.length > 0) {
        props[key] = Number(valStr);
      } else {
        props[key] = valStr;
      }
    }
  }

  // Nested blocks detection helper
  props._hasServerSideEncryption =
    fullText.includes('server_side_encryption_configuration') ||
    fullText.includes('aws_s3_bucket_server_side_encryption_configuration');

  props._hasVersioning =
    fullText.includes('versioning') ||
    fullText.includes('aws_s3_bucket_versioning');

  props._hasPublicAccessBlock =
    fullText.includes('aws_s3_bucket_public_access_block');

  return props;
}
