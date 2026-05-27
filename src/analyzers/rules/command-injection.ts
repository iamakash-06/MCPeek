import { SourceFile, SyntaxKind, Node, Identifier } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

// Re-export so existing imports from this file continue to work
export { findMCPToolHandlers } from "../mcp-handler.js";

const DANGEROUS_SINKS = new Set([
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "execFile",
  "execFileSync",
]);

export function detectCommandInjection(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);
    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();
      const funcName = callText.split(".").pop() ?? callText;

      if (!DANGEROUS_SINKS.has(funcName)) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const firstArg = args[0];
      const matchedName = [...tainted.keys()].find((p) =>
        containsIdentifier(firstArg, p)
      );

      if (matchedName !== undefined) {
        const lineNum = call.getStartLineNumber();
        const chain = tainted.get(matchedName)!;
        const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());

        findings.push({
          rule: "mcp-command-injection",
          severity: "critical",
          cwe: "CWE-78",
          file: filePath,
          line: lineNum,
          column,
          message: `MCP tool handler parameter flows to ${funcName}() without sanitization`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Use execFile() with a fixed command and validated argument list. Never pass user-controlled input directly to exec/spawn.",
          confidence: "high",
          taintChain: [...chain, `${funcName}() (line ${lineNum})`],
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
