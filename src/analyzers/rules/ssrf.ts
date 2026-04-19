import { SourceFile, SyntaxKind, Node } from "ts-morph";
import type { Finding } from "../../types.js";
import { findMCPToolHandlers } from "./command-injection.js";

const HTTP_SINKS = new Set([
  "fetch",
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "request",
  "head",
]);

// axios.get, axios.post, http.request, https.request, got(), ky()
const HTTP_CALLEE_PATTERNS = [
  /^fetch$/,
  /^axios\.(get|post|put|delete|patch|request|head)$/,
  /^http\.(get|request)$/,
  /^https\.(get|request)$/,
  /^got$/,
  /^ky\.(get|post|put|delete|patch)$/,
  /^superagent/,
  /^needle/,
];

export function detectSSRF(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const toolHandlers = findMCPToolHandlers(sourceFile);

  for (const { paramNames, handlerBody } of toolHandlers) {
    if (!handlerBody || paramNames.length === 0) continue;

    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();

      const isHttpSink = HTTP_CALLEE_PATTERNS.some((p) => p.test(callText));
      if (!isHttpSink) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const urlArg = args[0];
      const urlText = urlArg.getText();

      const usesHandlerParam = paramNames.some(
        (p) => urlText.includes(p) || containsIdentifier(urlArg, p)
      );

      if (!usesHandlerParam) continue;

      // Check for URL validation (allowlist pattern)
      const blockText = handlerBody.getText();
      const hasAllowlist =
        blockText.includes("allowedHosts") ||
        blockText.includes("allowedUrls") ||
        blockText.includes("ALLOWED_") ||
        blockText.includes(".startsWith('https://") ||
        blockText.includes('new URL(') && blockText.includes('.hostname');

      if (!hasAllowlist) {
        const lineNum = call.getStartLineNumber();

        findings.push({
          rule: "mcp-ssrf",
          severity: "high",
          cwe: "CWE-918",
          file: filePath,
          line: lineNum,
          column: 1,
          message: `User-controlled URL flows to ${callText}() without host validation — potential SSRF`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Validate the URL against an allowlist of permitted hostnames. Use new URL(input) and check .hostname against known-safe values.",
          confidence: "high",
        });
      }
    }
  }

  return findings;
}

function containsIdentifier(node: Node, name: string): boolean {
  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((id) => id.getText() === name);
}

function extractSnippet(
  sourceFile: SourceFile,
  lineNum: number,
  context: number
): string {
  const lines = sourceFile.getFullText().split("\n");
  const start = Math.max(0, lineNum - context - 1);
  const end = Math.min(lines.length, lineNum + context);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join("\n");
}
