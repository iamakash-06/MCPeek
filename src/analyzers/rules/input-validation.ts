import { SourceFile, SyntaxKind, CallExpression } from "ts-morph";
import type { Finding } from "../../types.js";

export function detectMissingInputValidation(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const expr = call.getExpression();
    const text = expr.getText();

    const isMCPRegistration =
      text.endsWith(".tool") ||
      text.endsWith(".addTool") ||
      text === "server.tool";

    if (!isMCPRegistration) continue;

    const args = call.getArguments();
    if (args.length < 2) continue;

    // server.tool(name, handler) — missing schema entirely
    if (args.length === 2) {
      const secondArg = args[1];
      const isHandler =
        secondArg.getKind() === SyntaxKind.ArrowFunction ||
        secondArg.getKind() === SyntaxKind.FunctionExpression;

      if (isHandler) {
        const lineNum = call.getStartLineNumber();
        findings.push({
          rule: "mcp-missing-input-validation",
          severity: "high",
          cwe: "CWE-20",
          file: filePath,
          line: lineNum,
          column: 1,
          message: "MCP tool registered without an input schema (no Zod validation)",
          evidence: extractSnippet(sourceFile, lineNum, 2),
          remediation:
            "Add a Zod schema as the second argument: server.tool(name, { param: z.string() }, handler)",
          confidence: "high",
        });
        continue;
      }
    }

    // server.tool(name, schema, handler) — check if schema uses raw z.any() or z.unknown()
    if (args.length >= 3) {
      const schemaArg = args[1];
      const schemaText = schemaArg.getText();

      if (schemaText.includes("z.any()") || schemaText.includes("z.unknown()")) {
        const lineNum = call.getStartLineNumber();
        findings.push({
          rule: "mcp-weak-input-validation",
          severity: "medium",
          cwe: "CWE-20",
          file: filePath,
          line: lineNum,
          column: 1,
          message: "MCP tool uses z.any() or z.unknown() — schema provides no real validation",
          evidence: extractSnippet(sourceFile, lineNum, 2),
          remediation:
            "Replace z.any()/z.unknown() with a specific Zod type (z.string(), z.number(), etc.)",
          confidence: "high",
        });
      }
    }
  }

  return findings;
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
