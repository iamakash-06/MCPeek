import { Node, Project, SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findTaintedReaching } from "../taint-match.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

const MUTATING_RE =
  /^(delete|remove|destroy|drop|revoke|update|write|insert|transfer|refund|charge|publish|unlink|archive|grant|cancel|terminate|rm|rmSync)/i;
const AUTHZ_RE =
  /authInfo|clientId|principal|\bowner|userId|\bsubject\b|permission|authori[sz]e|isOwner|assertOwner|\bcan[A-Z]\w*\(|\bacl\b/;

type CodecState = "bound" | "unbound";

const codecCache = new WeakMap<Project, Set<CodecState>>();

function codecStates(project: Project): Set<CodecState> {
  let states = codecCache.get(project);
  if (states) return states;
  states = new Set();
  for (const sf of project.getSourceFiles()) {
    if (!sf.getFullText().includes("createRequestStateCodec")) continue;
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!call.getExpression().getText().endsWith("createRequestStateCodec")) continue;
      const options = call.getArguments()[0]?.asKind(SyntaxKind.ObjectLiteralExpression);
      states.add(options?.getProperty("bind") ? "bound" : "unbound");
    }
  }
  codecCache.set(project, states);
  return states;
}

function unwrapCall(node: Node): Node {
  while (Node.isAwaitExpression(node) || Node.isAsExpression(node) || Node.isNonNullExpression(node) || Node.isParenthesizedExpression(node)) {
    node = node.getExpression();
  }
  return node;
}

function isStateRead(node: Node): boolean {
  const call = unwrapCall(node).asKind(SyntaxKind.CallExpression);
  return !!call && /(^|\.)requestState$/.test(call.getExpression().getText());
}

function stateSeeds(body: Node): string[] {
  const seeds: string[] = [];
  for (const decl of body.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init || !isStateRead(init)) continue;
    const name = decl.getNameNode();
    if (Node.isIdentifier(name)) seeds.push(name.getText());
    else name.getDescendantsOfKind(SyntaxKind.BindingElement).forEach((el) => seeds.push(el.getNameNode().getText()));
  }
  return seeds;
}

function isGuarded(sink: Node, body: Node, seeds: string[]): boolean {
  if (AUTHZ_RE.test(sink.getText())) return true;
  let child: Node = sink;
  for (let parent = sink.getParent(); parent && child !== body; child = parent, parent = parent.getParent()) {
    if (Node.isIfStatement(parent) && parent.getThenStatement() === child && AUTHZ_RE.test(parent.getExpression().getText())) return true;
    if (!Node.isBlock(parent) && !Node.isSourceFile(parent)) continue;
    for (const stmt of parent.getStatements()) {
      if (stmt === child) break;
      if (Node.isIfStatement(stmt)) {
        const cond = stmt.getExpression().getText();
        if (!AUTHZ_RE.test(cond) && seeds.some((s) => cond.includes(s))) continue;
      }
      if (AUTHZ_RE.test(stmt.getText())) return true;
    }
  }
  return false;
}

export function detectRequestStateAuthzGap(sourceFile: SourceFile, options: HandlerScanOptions = {}): Finding[] {
  if (!sourceFile.getFullText().includes("requestState")) return [];
  const states = codecStates(sourceFile.getProject());
  if (states.has("bound")) return [];

  const findings: Finding[] = [];
  const seen = new Set<number>();

  for (const handler of findMCPToolHandlers(sourceFile, options)) {
    const body = handler.handlerBody;
    if (!body) continue;
    const seeds = stateSeeds(body);
    if (seeds.length === 0) continue;
    const tainted = getTaintedNames(body, seeds);

    for (const call of body.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callee = call.getExpression().getText();
      if (!MUTATING_RE.test(callee.split(".").pop() ?? callee)) continue;
      const hit = call.getArguments().map((a) => findTaintedReaching(a, tainted)).find(Boolean);
      if (!hit || isGuarded(call, body, seeds)) continue;

      const line = call.getStartLineNumber();
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push({
        rule: "mcp-requeststate-authz-gap",
        severity: "high",
        cwe: "CWE-639",
        file: sourceFile.getFilePath(),
        line,
        column: sourceFile.getLineAndColumnAtPos(call.getStart()).column,
        message: "A value read from requestState reaches a mutating call with no authorization check on this path, and no codec binds state to the caller",
        evidence: extractSnippet(sourceFile, line, 3),
        remediation: "Re-check ownership against ctx.http.authInfo before acting on state, or pass bind to createRequestStateCodec.",
        confidence: states.has("unbound") ? "medium" : "low",
        taintChain: [`${hit.root} (requestState)`, ...hit.chain.slice(1), `${callee}() (line ${line})`],
      });
    }
  }
  return findings;
}
