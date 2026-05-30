import { SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findTaintedReaching } from "../taint-match.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

const CALL_SINKS = new Set([
  "eval",
  "runInContext",
  "runInNewContext",
  "runInThisContext",
  "compileFunction",
]);

const NEW_SINKS = new Set(["Function", "Script"]);

export function detectCodeInjection(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);

    for (const call of handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callText = call.getExpression().getText();
      const funcName = callText.split(".").pop() ?? callText;
      if (!CALL_SINKS.has(funcName)) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const matched = findTaintedReaching(args[0], tainted);
      if (!matched) continue;

      const lineNum = call.getStartLineNumber();
      const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());
      findings.push(
        makeFinding(
          filePath,
          lineNum,
          column,
          `${funcName}()`,
          matched.chain,
          sourceFile
        )
      );
    }

    for (const expr of handlerBody.getDescendantsOfKind(SyntaxKind.NewExpression)) {
      const exprText = expr.getExpression().getText();
      const ctorName = exprText.split(".").pop() ?? exprText;
      if (!NEW_SINKS.has(ctorName)) continue;

      const args = expr.getArguments();
      if (args.length === 0) continue;

      let matched;
      for (const arg of args) {
        matched = findTaintedReaching(arg, tainted);
        if (matched) break;
      }
      if (!matched) continue;

      const lineNum = expr.getStartLineNumber();
      const { column } = sourceFile.getLineAndColumnAtPos(expr.getStart());
      findings.push(
        makeFinding(
          filePath,
          lineNum,
          column,
          `new ${ctorName}()`,
          matched.chain,
          sourceFile
        )
      );
    }
  }

  return findings;
}

function makeFinding(
  filePath: string,
  line: number,
  column: number,
  sinkLabel: string,
  chain: string[],
  sourceFile: SourceFile
): Finding {
  return {
    rule: "mcp-code-injection",
    severity: "critical",
    cwe: "CWE-94",
    file: filePath,
    line,
    column,
    message: `MCP tool handler parameter flows to ${sinkLabel} without sanitization`,
    evidence: extractSnippet(sourceFile, line, 3),
    remediation:
      "Never pass user-controlled input to eval, new Function, or the vm module. Use a safe parser or a sandboxed expression library with an explicit allowlist.",
    confidence: "high",
    taintChain: [...chain, `${sinkLabel} (line ${line})`],
  };
}

