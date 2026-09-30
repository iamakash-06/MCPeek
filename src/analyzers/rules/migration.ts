import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";

const PUSH_CALLS = new Set(["elicitInput", "createMessage", "listRoots"]);
const PUSH_RECEIVER_RE = /\b(server|ctx|extra|context|mcpReq)\b/i;
const PUSH_METHODS = new Set(["elicitation/create", "sampling/createMessage", "roots/list"]);
const REMOVED_METHODS = new Set(["ping", "logging/setLevel", "notifications/roots/list_changed"]);
const REMOVED_SCHEMAS = new Set(["SetLevelRequestSchema", "RootsListChangedNotificationSchema"]);
const REMOVED_CALLS = new Set(["ping", "sendRootsListChanged"]);
const PEER_RE = /\b(server|client)\b/i;

function finding(sf: SourceFile, node: Node, rule: string, message: string, remediation: string): Finding {
  const line = node.getStartLineNumber();
  return {
    rule,
    severity: "low",
    cwe: "CWE-477",
    file: sf.getFilePath(),
    line,
    column: sf.getLineAndColumnAtPos(node.getStart()).column,
    message,
    evidence: extractSnippet(sf, line, 3),
    remediation,
    confidence: "medium",
  };
}

function methodLiteral(node: Node): string | undefined {
  if (!Node.isPropertyAssignment(node) || node.getName() !== "method") return undefined;
  const init = node.getInitializer();
  return init && (Node.isStringLiteral(init) || Node.isNoSubstitutionTemplateLiteral(init)) ? init.getLiteralText() : undefined;
}

export function detectMigrationReadiness(sourceFile: SourceFile): Finding[] {
  const text = sourceFile.getFullText();
  if (!text.includes("@modelcontextprotocol/")) return [];
  const findings: Finding[] = [];

  const pushRemediation = "Return inputRequired({ inputRequests, requestState }) and handle the answer on the retried call.";
  const removedRemediation = "Remove the call; this method no longer exists in 2026-07-28.";

  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const callee = call.getExpression().asKind(SyntaxKind.PropertyAccessExpression);
    if (!callee) continue;
    const name = callee.getName();
    const receiver = callee.getExpression().getText();

    if (PUSH_CALLS.has(name) && (name === "elicitInput" || PUSH_RECEIVER_RE.test(receiver))) {
      findings.push(
        finding(sourceFile, call, "mcp-migration-push-request", `${name}() pushes a server-initiated request, which throws on 2026-07-28 requests`, pushRemediation)
      );
    } else if (REMOVED_CALLS.has(name) && PEER_RE.test(receiver)) {
      findings.push(finding(sourceFile, call, "mcp-migration-removed-method", `${name}() calls a method removed in 2026-07-28`, removedRemediation));
    } else if (/^(setRequestHandler|setNotificationHandler|request|notification)$/.test(name)) {
      const first = call.getArguments()[0];
      if (first && Node.isIdentifier(first) && REMOVED_SCHEMAS.has(first.getText())) {
        findings.push(finding(sourceFile, call, "mcp-migration-removed-method", `${first.getText()} belongs to a method removed in 2026-07-28`, removedRemediation));
      }
    }
  }

  for (const prop of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    const method = methodLiteral(prop);
    if (!method) continue;
    if (PUSH_METHODS.has(method)) {
      findings.push(finding(sourceFile, prop, "mcp-migration-push-request", `"${method}" is a server-initiated request, unsupported on 2026-07-28 requests`, pushRemediation));
    } else if (REMOVED_METHODS.has(method)) {
      findings.push(finding(sourceFile, prop, "mcp-migration-removed-method", `"${method}" is removed in 2026-07-28`, removedRemediation));
    }
  }

  return findings;
}
