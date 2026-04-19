import {
  SourceFile,
  SyntaxKind,
  Node,
  CallExpression,
  Identifier,
} from "ts-morph";
import type { Finding } from "../../types.js";

const DANGEROUS_SINKS = new Set([
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "execFile",
  "execFileSync",
]);

export function detectCommandInjection(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const toolHandlers = findMCPToolHandlers(sourceFile);

  for (const { paramNames, handlerBody } of toolHandlers) {
    if (!handlerBody || paramNames.length === 0) continue;

    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();
      const funcName = callText.split(".").pop() ?? callText;

      if (!DANGEROUS_SINKS.has(funcName)) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const firstArg = args[0];
      const argText = firstArg.getText();

      const usesHandlerParam = paramNames.some(
        (p) =>
          argText.includes(p) ||
          containsIdentifier(firstArg, p)
      );

      if (usesHandlerParam) {
        const lineNum = call.getStartLineNumber();
        const snippet = extractSnippet(sourceFile, lineNum, 3);

        findings.push({
          rule: "mcp-command-injection",
          severity: "critical",
          cwe: "CWE-78",
          file: filePath,
          line: lineNum,
          column: call.getStart() - sourceFile.getLineAndColumnAtPos(call.getStart()).column + 1,
          message: `MCP tool handler parameter flows to ${funcName}() without sanitization`,
          evidence: snippet,
          remediation:
            "Use execFile() with a fixed command and validated argument list. Never pass user-controlled input directly to exec/spawn.",
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
    .some((id: Identifier) => id.getText() === name);
}

export function findMCPToolHandlers(
  sourceFile: SourceFile
): Array<{ paramNames: string[]; handlerBody: Node | undefined }> {
  const results: Array<{ paramNames: string[]; handlerBody: Node | undefined }> = [];

  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const expr = call.getExpression();
    const text = expr.getText();

    const isMCPRegistration =
      text.endsWith(".tool") ||
      text.endsWith(".setRequestHandler") ||
      text.endsWith(".addTool") ||
      text === "server.tool" ||
      text === "server.setRequestHandler";

    if (!isMCPRegistration) continue;

    const args = call.getArguments();
    if (args.length < 2) continue;

    // Patterns:
    //   server.tool(name, handler)          → args[1] is handler
    //   server.tool(name, schema, handler)  → args[2] is handler
    const lastArg = args[args.length - 1];
    const handlerFn =
      lastArg.getKind() === SyntaxKind.ArrowFunction ||
      lastArg.getKind() === SyntaxKind.FunctionExpression
        ? lastArg
        : undefined;

    if (!handlerFn) continue;

    // Extract destructured param names from handler's first parameter
    const params = handlerFn.getDescendantsOfKind(SyntaxKind.Parameter);
    const paramNames: string[] = [];

    for (const param of params.slice(0, 1)) {
      const binding = param.getNameNode();
      if (binding.getKind() === SyntaxKind.ObjectBindingPattern) {
        binding
          .getDescendantsOfKind(SyntaxKind.BindingElement)
          .forEach((el) => {
            const nameNode = el.getNameNode();
            if (nameNode) paramNames.push(nameNode.getText());
          });
      } else {
        paramNames.push(binding.getText());
      }
    }

    const body =
      handlerFn.getDescendantsOfKind(SyntaxKind.Block)[0] ?? handlerFn;

    results.push({ paramNames, handlerBody: body });
  }

  return results;
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
