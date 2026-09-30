import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames, type TaintMap } from "../taint-tracker.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

const HTML_ESCAPERS = ["escapeHtml", "escapeHTML", "htmlEscape", "escape", "he.escape", "DOMPurify.sanitize", "purify.sanitize"];
const HTML_MIME_RE = /text\/html|MIME_TYPE/;

function propInitializer(obj: Node, name: string): Node | undefined {
  const prop = obj.asKind(SyntaxKind.ObjectLiteralExpression)?.getProperty(name);
  if (!prop) return undefined;
  return Node.isPropertyAssignment(prop) ? prop.getInitializer() : Node.isShorthandPropertyAssignment(prop) ? prop.getNameNode() : undefined;
}

function firstUnescapedTaint(node: Node, tainted: TaintMap): string | undefined {
  const escaped = (n: Node) =>
    !!n.getFirstAncestor(
      (p) => Node.isCallExpression(p) && HTML_ESCAPERS.includes(p.getExpression().getText()) && node.containsRange(p.getPos(), p.getEnd())
    );
  const refs = [
    ...node.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression),
    ...node.getDescendantsOfKind(SyntaxKind.Identifier),
    ...(Node.isIdentifier(node) ? [node] : []),
  ];
  return refs.find((r) => tainted.has(r.getText()) && !escaped(r))?.getText();
}

export function detectAppsHtmlXss(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): Finding[] {
  const text = sourceFile.getFullText();
  if (!/text\/html|MIME_TYPE/.test(text)) return [];
  const findings: Finding[] = [];

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;
    const tainted = getTaintedNames(handlerBody, paramNames, { extraBreakers: HTML_ESCAPERS });

    for (const obj of handlerBody.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
      const mime = propInitializer(obj, "mimeType");
      const html = propInitializer(obj, "text");
      if (!mime || !html || !HTML_MIME_RE.test(mime.getText())) continue;

      const name = firstUnescapedTaint(html, tainted);
      if (!name) continue;

      const line = html.getStartLineNumber();
      findings.push({
        rule: "mcp-apps-html-xss",
        severity: "high",
        cwe: "CWE-79",
        file: sourceFile.getFilePath(),
        line,
        column: sourceFile.getLineAndColumnAtPos(html.getStart()).column,
        message: "MCP Apps HTML resource is built from unescaped tool input (stored XSS in the host)",
        evidence: extractSnippet(sourceFile, line, 3),
        remediation: "HTML-escape every interpolated value, or pass data through structuredContent and render it client-side with textContent.",
        confidence: "medium",
        taintChain: [...tainted.get(name)!.chain, `HTML resource text (line ${line})`],
      });
    }
  }
  return findings;
}
