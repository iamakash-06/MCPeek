import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";
import { resolveSchemaDefinition } from "../cross-file.js";

const CSP_KEYS = /^(connect|resource|frame|baseUri|worker)Domains$|^(connect|resource|frame|base_uri|worker)_domains$/;
const BROAD_SOURCE_RE = /^(\*|(https?|wss?):(\/\/\*)?|(https?|wss?):\/\/\*(:\*)?)$/;

export function detectAppsWildcardCsp(sourceFile: SourceFile): Finding[] {
  if (!/Domains|_domains/.test(sourceFile.getFullText())) return [];
  const findings: Finding[] = [];

  for (const prop of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    if (!CSP_KEYS.test(prop.getName())) continue;
    const init = prop.getInitializer();
    const list = init && resolveSchemaDefinition(init).asKind(SyntaxKind.ArrayLiteralExpression);
    if (!list) continue;
    const broad = list
      .getElements()
      .filter((e) => Node.isStringLiteral(e) || Node.isNoSubstitutionTemplateLiteral(e))
      .map((e) => (e as Node & { getLiteralText(): string }).getLiteralText())
      .find((v) => BROAD_SOURCE_RE.test(v));
    if (!broad) continue;

    const line = prop.getStartLineNumber();
    findings.push({
      rule: "mcp-apps-wildcard-csp",
      severity: "medium",
      cwe: "CWE-693",
      file: sourceFile.getFilePath(),
      line,
      column: sourceFile.getLineAndColumnAtPos(prop.getStart()).column,
      message: `MCP Apps CSP allows "${broad}" in ${prop.getName()}, so the app iframe can reach or load from any origin`,
      evidence: extractSnippet(sourceFile, line, 3),
      remediation: "List the exact origins the app needs instead of a wildcard.",
      confidence: "high",
    });
  }
  return findings;
}
