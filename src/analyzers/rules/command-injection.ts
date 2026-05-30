import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames, TaintMap } from "../taint-tracker.js";
import { findTaintedReaching } from "../taint-match.js";
import { forEachTaintedCallTarget } from "../cross-file.js";
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

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);
    scanBody(handlerBody, tainted, "high", findings);

    forEachTaintedCallTarget(handlerBody, tainted, sourceFile, (calleeBody, calleeTainted) => {
      scanBody(calleeBody, calleeTainted, "medium", findings);
    });
  }

  return findings;
}

function scanBody(
  body: Node,
  tainted: TaintMap,
  confidence: "high" | "medium",
  findings: Finding[]
): void {
  const sourceFile = body.getSourceFile();
  const filePath = sourceFile.getFilePath();

  for (const call of body.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callText = call.getExpression().getText();
    const funcName = callText.split(".").pop() ?? callText;
    if (!DANGEROUS_SINKS.has(funcName)) continue;

    const args = call.getArguments();
    if (args.length === 0) continue;

    const matched = findTaintedReaching(args[0], tainted);
    if (!matched) continue;

    const lineNum = call.getStartLineNumber();
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
      confidence,
      taintChain: [...matched.chain, `${funcName}() (line ${lineNum})`],
    });
  }
}
