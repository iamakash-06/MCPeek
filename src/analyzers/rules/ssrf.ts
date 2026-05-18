import { SourceFile, SyntaxKind, Node, Identifier } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findMCPToolHandlers } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

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

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);
    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();

      const isHttpSink = HTTP_CALLEE_PATTERNS.some((p) => p.test(callText));
      if (!isHttpSink) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const urlArg = args[0];
      const urlText = urlArg.getText();

      const matchedName = [...tainted.keys()].find((p) =>
        containsIdentifier(urlArg, p)
      );

      if (matchedName === undefined) continue;

      if (
        urlArg.getKind() === SyntaxKind.TemplateExpression ||
        urlText.startsWith("`")
      ) {
        const hardcodedBase =
          /^`https?:\/\/[^$`]+\/\$\{/.test(urlText) ||
          /^\`\$\{[A-Z_]+\}\//.test(urlText); // ${CONSTANT}/path
        if (hardcodedBase) continue;
      }

      // Check for URL validation (allowlist pattern)
      const blockText = handlerBody.getText();
      const hasAllowlist =
        blockText.includes("allowedHosts") ||
        blockText.includes("allowedUrls") ||
        blockText.includes("ALLOWED_") ||
        blockText.includes(".startsWith('https://") ||
        (blockText.includes("new URL(") && blockText.includes(".hostname"));

      if (!hasAllowlist) {
        const lineNum = call.getStartLineNumber();
        const chain = tainted.get(matchedName)!;
        const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());

        findings.push({
          rule: "mcp-ssrf",
          severity: "high",
          cwe: "CWE-918",
          file: filePath,
          line: lineNum,
          column,
          message: `User-controlled URL flows to ${callText}() without host validation — potential SSRF`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Validate the URL against an allowlist of permitted hostnames. Use new URL(input) and check .hostname against known-safe values.",
          confidence: "high",
          taintChain: [...chain, `${callText}() (line ${lineNum})`],
        });
      }
    }
  }

  return findings;
}

function containsIdentifier(node: Node, name: string): boolean {
  if (node.getKind() === SyntaxKind.Identifier && node.getText() === name) {
    return true;
  }

  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((id: Identifier) => id.getText() === name);
}
