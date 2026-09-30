import { Node, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";

const STORE_NAME_RE = /session|transport/i;
const GENERATOR_RE = /random|uuid|nanoid|Date\.now|Math\./i;
const SESSION_KEY_RE = /session[-_]?id|mcp-session-id/i;

function finding(sf: SourceFile, node: Node, severity: Finding["severity"], message: string): Finding {
  const line = node.getStartLineNumber();
  return {
    rule: "mcp-session-keyed-state",
    severity,
    cwe: "CWE-362",
    file: sf.getFilePath(),
    line,
    column: sf.getLineAndColumnAtPos(node.getStart()).column,
    message,
    evidence: extractSnippet(sf, line, 3),
    remediation:
      "Keep no per-session state in process memory: carry state in a signed requestState or tool arguments, or store it in a shared store keyed by an application handle.",
    confidence: "medium",
  };
}

function isEmptyStore(init: Node | undefined): boolean {
  if (!init) return false;
  if (Node.isObjectLiteralExpression(init)) return init.getProperties().length === 0;
  if (Node.isNewExpression(init)) return /^(Map|WeakMap)$/.test(init.getExpression().getText());
  return false;
}

function sessionKeyed(node: Node): boolean {
  return SESSION_KEY_RE.test(node.getText());
}

export function detectSessionKeyedState(sourceFile: SourceFile): Finding[] {
  const text = sourceFile.getFullText();
  if (!/session/i.test(text)) return [];
  const findings: Finding[] = [];

  const stores = new Set<string>();
  for (const decl of sourceFile.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    if (STORE_NAME_RE.test(decl.getName()) && isEmptyStore(decl.getInitializer())) stores.add(decl.getName());
  }

  for (const name of stores) {
    const use = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression).find((call) => {
      const pa = call.getExpression().asKind(SyntaxKind.PropertyAccessExpression);
      const key = call.getArguments()[0];
      return pa?.getExpression().getText() === name && ["get", "set", "has", "delete"].includes(pa.getName()) && !!key && sessionKeyed(key);
    }) ?? sourceFile.getDescendantsOfKind(SyntaxKind.ElementAccessExpression).find((el) => {
      const key = el.getArgumentExpression();
      return el.getExpression().getText() === name && !!key && sessionKeyed(key);
    });
    if (use) {
      findings.push(finding(sourceFile, use, "medium", `In-process map "${name}" is keyed by session id, which does not exist in 2026-07-28 and breaks when requests reach another instance`));
    }
  }

  for (const prop of sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    if (prop.getName() !== "sessionIdGenerator") continue;
    const init = prop.getInitializer();
    if (!init || !GENERATOR_RE.test(init.getText())) continue;
    findings.push(finding(sourceFile, prop, "low", "Transport generates session ids, a stateful pattern removed in 2026-07-28"));
  }

  return findings;
}
