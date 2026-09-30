import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";
import { SECRET_NAME_RE } from "./request-state.js";

export function detectSensitiveHeaderMapping(sourceFile: SourceFile): Finding[] {
  if (!sourceFile.getFullText().includes("x-mcp-header")) return [];
  const findings: Finding[] = [];

  for (const prop of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    if (prop.getName().replace(/^['"`]|['"`]$/g, "") !== "x-mcp-header") continue;

    const field = prop.getFirstAncestor(
      (a): a is Node & { getName(): string } =>
        Node.isPropertyAssignment(a) && a !== prop && !a.getName().startsWith("x-mcp")
    );
    const fieldName = field?.getName().replace(/^['"`]|['"`]$/g, "");
    if (!fieldName || !SECRET_NAME_RE.test(fieldName)) continue;

    const line = prop.getStartLineNumber();
    findings.push({
      rule: "mcp-header-sensitive",
      severity: "medium",
      cwe: "CWE-200",
      file: sourceFile.getFilePath(),
      line,
      column: sourceFile.getLineAndColumnAtPos(prop.getStart()).column,
      message: `x-mcp-header mirrors secret-looking argument "${fieldName}" into an HTTP header, exposing it to proxies and logs`,
      evidence: extractSnippet(sourceFile, line, 3),
      remediation: "Remove x-mcp-header from secret fields; mirror only routing values such as region or tenant.",
      confidence: "high",
    });
  }
  return findings;
}
