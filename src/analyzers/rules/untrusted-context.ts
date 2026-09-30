import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";

const AUTH_KEY_RE = /user|tenant|role|admin|scope|permission|principal|identity|owner|org|account|email|trusted|internal|privileg/i;
const ROUTING_HEADER_RE = /^mcp-(method|name)$/i;
const BODY_CROSSCHECK_RE = /params\??\.name|(body|message|request|rpc|payload)\??\.method/;
const IGNORED_HEADERS = /^(user-agent|authorization|proxy-authorization)$/i;

const isRequestHeaders = (recv: string) => /(^|\.)headers$/.test(recv) && !/\b(res|response)\b/i.test(recv);

function accessedKey(node: Node): { key: string; source: "_meta" | "header" } | undefined {
  if (Node.isPropertyAccessExpression(node)) {
    const recv = node.getExpression().getText().replace(/\?$/, "");
    if (/(^|\.)_meta$/.test(recv)) return { key: node.getName(), source: "_meta" };
    if (isRequestHeaders(recv)) return { key: node.getName(), source: "header" };
  }
  if (Node.isElementAccessExpression(node)) {
    const arg = node.getArgumentExpression();
    const key = arg && (Node.isStringLiteral(arg) || Node.isNoSubstitutionTemplateLiteral(arg)) ? arg.getLiteralText() : undefined;
    const recv = node.getExpression().getText();
    if (key && /(^|\.)_meta$/.test(recv)) return { key, source: "_meta" };
    if (key && isRequestHeaders(recv)) return { key, source: "header" };
  }
  if (Node.isCallExpression(node)) {
    const pa = node.getExpression().asKind(SyntaxKind.PropertyAccessExpression);
    const arg = node.getArguments()[0];
    if (pa?.getName() === "get" && isRequestHeaders(pa.getExpression().getText()) && arg && Node.isStringLiteral(arg)) {
      return { key: arg.getLiteralText(), source: "header" };
    }
    if ((pa?.getName() === "header" || pa?.getName() === "getHeader") && arg && Node.isStringLiteral(arg) && !/\b(res|response)\b/i.test(pa.getExpression().getText())) {
      return { key: arg.getLiteralText(), source: "header" };
    }
  }
  return undefined;
}

function decisionContext(node: Node): "condition" | "assignment" | undefined {
  let child: Node = node;
  for (let parent = node.getParent(); parent; child = parent, parent = parent.getParent()) {
    if (Node.isIfStatement(parent) && parent.getExpression() === child) return "condition";
    if (Node.isConditionalExpression(parent) && parent.getCondition() === child) return "condition";
    if (Node.isSwitchStatement(parent) && parent.getExpression() === child) return "condition";
    if (Node.isBinaryExpression(parent)) {
      const op = parent.getOperatorToken().getText();
      if (op === "&&" || op === "||" || op === "===" || op === "!==" || op === "==" || op === "!=") continue;
    }
    if (Node.isParenthesizedExpression(parent) || Node.isPrefixUnaryExpression(parent) || Node.isAsExpression(parent) || Node.isNonNullExpression(parent) || Node.isCallExpression(parent) && parent.getExpression() !== child) continue;
    if (Node.isVariableDeclaration(parent) && AUTH_KEY_RE.test(parent.getName())) return "assignment";
    return undefined;
  }
  return undefined;
}

export function detectUntrustedContextAuthz(sourceFile: SourceFile): Finding[] {
  const text = sourceFile.getFullText();
  const hasRoutingHeader = /mcp-(method|name)/i.test(text);
  if ((!text.includes("@modelcontextprotocol/") || !/_meta|headers/.test(text)) && !hasRoutingHeader) return [];
  const findings: Finding[] = [];
  const seen = new Set<number>();

  const candidates = [
    ...sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression),
    ...sourceFile.getDescendantsOfKind(SyntaxKind.ElementAccessExpression),
    ...sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression),
  ];
  for (const node of candidates) {
    const hit = accessedKey(node);
    if (!hit) continue;
    const routing = hit.source === "header" && ROUTING_HEADER_RE.test(hit.key);
    if (!routing && (!AUTH_KEY_RE.test(hit.key) || IGNORED_HEADERS.test(hit.key))) continue;
    const context = decisionContext(node);
    if (!context) continue;
    const line = node.getStartLineNumber();
    if (seen.has(line)) continue;
    seen.add(line);

    if (routing) {
      const fn = node.getFirstAncestor((a) => Node.isFunctionLikeDeclaration(a));
      if (BODY_CROSSCHECK_RE.test((fn ?? sourceFile).getText())) continue;
      findings.push({
        rule: "mcp-header-trust",
        severity: "medium",
        cwe: "CWE-807",
        file: sourceFile.getFilePath(),
        line,
        column: sourceFile.getLineAndColumnAtPos(node.getStart()).column,
        message: `Header "${hit.key}" drives a decision without being checked against the JSON-RPC body, so a client can send a header that disagrees with the request`,
        evidence: extractSnippet(sourceFile, line, 3),
        remediation: "Treat Mcp-Method and Mcp-Name as routing hints only and reject requests whose body method or params.name differ.",
        confidence: "medium",
      });
      continue;
    }

    findings.push({
      rule: "mcp-meta-authz",
      severity: "medium",
      cwe: "CWE-807",
      file: sourceFile.getFilePath(),
      line,
      column: sourceFile.getLineAndColumnAtPos(node.getStart()).column,
      message: `Client-supplied ${hit.source === "_meta" ? "_meta" : "header"} value "${hit.key}" is used to make an authorization or identity decision`,
      evidence: extractSnippet(sourceFile, line, 3),
      remediation: "Derive identity and permissions from verified auth info (ctx.http.authInfo), never from _meta or request headers.",
      confidence: context === "condition" ? "medium" : "low",
    });
  }
  return findings;
}
