import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames, TaintMap } from "../taint-tracker.js";
import { findTaintedReaching } from "../taint-match.js";
import { forEachTaintedCallTarget } from "../cross-file.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

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

export function detectSSRF(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): Finding[] {
  const findings: Finding[] = [];

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);
    scanBody(handlerBody, tainted, handlerBody, "high", findings);

    forEachTaintedCallTarget(handlerBody, tainted, sourceFile, (calleeBody, calleeTainted) => {
      scanBody(calleeBody, calleeTainted, calleeBody, "medium", findings);
    });
  }

  return findings;
}

const ALLOWLIST_METHODS = new Set(["includes", "indexOf", "has", "test", "startsWith"]);
const HOST_RE = /host|hostname|url|origin|domain/i;
const ALLOW_RE = /allow|whitelist|permit|safe|valid/i;

/**
 * True for a genuine host-validation comparison (allowlist method call on the
 * host, or host equality check) rather than a mere allowlist-identifier mention.
 */
function hasHostValidation(scope: Node): boolean {
  for (const call of scope.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const pa = call.getExpression().asKind(SyntaxKind.PropertyAccessExpression);
    if (!pa) continue;
    if (!ALLOWLIST_METHODS.has(pa.getName())) continue;
    const receiver = pa.getExpression().getText();
    const argText = call.getArguments().map((a) => a.getText()).join(",");
    const hostInvolved = HOST_RE.test(receiver) || HOST_RE.test(argText);
    const allowInvolved = ALLOW_RE.test(receiver) || ALLOW_RE.test(argText);
    if (hostInvolved && allowInvolved) return true;
    if (ALLOW_RE.test(receiver) && HOST_RE.test(argText)) return true;
  }

  for (const bin of scope.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    const op = bin.getOperatorToken().getText();
    if (op !== "===" && op !== "!==" && op !== "==" && op !== "!=") continue;
    const sides = [bin.getLeft().getText(), bin.getRight().getText()];
    if (sides.some((s) => /hostname|\bhost\b/i.test(s))) return true;
  }
  return false;
}

function scanBody(
  body: Node,
  tainted: TaintMap,
  allowlistScope: Node,
  confidence: "high" | "medium",
  findings: Finding[]
): void {
  const sourceFile = body.getSourceFile();
  const filePath = sourceFile.getFilePath();

  for (const call of body.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callText = call.getExpression().getText();
    if (!HTTP_CALLEE_PATTERNS.some((p) => p.test(callText))) continue;

    const args = call.getArguments();
    if (args.length === 0) continue;

    const urlArg = args[0];
    const urlText = urlArg.getText();
    const matched = findTaintedReaching(urlArg, tainted);
    if (!matched) continue;

    if (
      urlArg.getKind() === SyntaxKind.TemplateExpression ||
      urlText.startsWith("`")
    ) {
      const hardcodedBase =
        /^`https?:\/\/[^$`]+\/\$\{/.test(urlText) ||
        /^\`\$\{[A-Z_]+\}\//.test(urlText);
      if (hardcodedBase) continue;
    }

    if (hasHostValidation(allowlistScope)) continue;

    const lineNum = call.getStartLineNumber();
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
      confidence,
      taintChain: [...matched.chain, `${callText}() (line ${lineNum})`],
    });
  }
}
