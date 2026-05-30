/**
 * Intra-function taint tracking for TypeScript MCP handler bodies.
 *
 * Given a set of source parameter names, walks variable declarations and
 * assignments in a handler body and returns a TaintMap: every alias that
 * carries tainted data, keyed by its expression text.
 *
 * Map keys:
 *   "cmd"          → handler param
 *   "command"      → const command = cmd
 *   "opts.command" → opts.command = cmd
 *
 * Each entry carries:
 *   chain — breadcrumb strings used by the SARIF / Markdown reporters
 *   path  — dotted property path from the root, e.g. ["opts","command"]
 *   root  — the original handler-param name the chain stems from
 */

import { Node, SyntaxKind } from "ts-morph";

export interface TaintEntry {
  chain: string[];
  path: string[];
  root: string;
}

export type TaintMap = Map<string, TaintEntry>;

export interface TaintOptions {
  /**
   * Function names that neutralise their tainted argument: when the RHS of an
   * assignment is a call to one of these, the LHS is not propagated as tainted.
   * Defaults cover `shell-escape`, `shell-quote`, and common sanitiser names.
   */
  extraBreakers?: string[];
}

const DEFAULT_TAINT_BREAKERS = new Set([
  "shellEscape",
  "shellQuote",
  "shellescape",
  "shellquote",
  "escape",
  "quote",
  "sanitize",
  "sanitizeHtml",
  "sanitizeUrl",
  "sanitizePath",
  "validateAndNormalize",
  "encodeURIComponent",
]);

export function getTaintedNames(
  handlerBody: Node,
  paramNames: string[],
  options: TaintOptions = {}
): TaintMap {
  const breakers = new Set(DEFAULT_TAINT_BREAKERS);
  for (const name of options.extraBreakers ?? []) breakers.add(name);
  const tainted: TaintMap = new Map();
  for (const p of paramNames) {
    tainted.set(p, { chain: [`${p} (handler param)`], path: [p], root: p });
  }

  const decls = handlerBody.getDescendantsOfKind(SyntaxKind.VariableDeclaration);

  let changed = true;
  let passes = 0;
  while (changed && passes < 4) {
    changed = false;
    passes++;

    for (const decl of decls) {
      const init = decl.getInitializer();
      if (!init) continue;
      if (isSanitizerCall(init, breakers)) continue;

      const nameNode = (decl as any).getNameNode?.();
      if (!nameNode) continue;

      if (nameNode.getKind() === SyntaxKind.Identifier) {
        const name = nameNode.getText();
        if (tainted.has(name)) continue;

        const match = findFirstTaintedIn(init, tainted);
        if (match) {
          const src = tainted.get(match)!;
          const line = decl.getStartLineNumber();
          tainted.set(name, {
            chain: [...src.chain, `${name} (line ${line})`],
            path: [name],
            root: src.root,
          });
          changed = true;
        }
      } else if (nameNode.getKind() === SyntaxKind.ObjectBindingPattern) {
        const match = findFirstTaintedIn(init, tainted);
        if (!match) continue;
        const src = tainted.get(match)!;
        const line = decl.getStartLineNumber();
        nameNode
          .getDescendantsOfKind(SyntaxKind.BindingElement)
          .forEach((el: any) => {
            const elName = el.getNameNode?.()?.getText();
            if (elName && !tainted.has(elName)) {
              tainted.set(elName, {
                chain: [...src.chain, `${elName} (line ${line})`],
                path: [elName],
                root: src.root,
              });
              changed = true;
            }
          });
      }
    }
  }

  // Imperative assignments: `let x; x = param` and `opts.field = param`
  const assignments = handlerBody.getDescendantsOfKind(SyntaxKind.BinaryExpression);
  for (const assign of assignments) {
    if (assign.getOperatorToken().getText() !== "=") continue;
    const lhsText = assign.getLeft().getText().trim();
    if (tainted.has(lhsText)) continue;

    const rhs = assign.getRight();
    if (isSanitizerCall(rhs, breakers)) continue;

    const match = findFirstTaintedIn(rhs, tainted);
    if (!match) continue;

    const src = tainted.get(match)!;
    const line = assign.getStartLineNumber();
    const lhsPath = lhsText.split(".");
    tainted.set(lhsText, {
      chain: [...src.chain, `${lhsText} (line ${line})`],
      path: lhsPath,
      root: lhsPath[0] || src.root,
    });
  }

  return tainted;
}

export function findFirstTaintedIn(node: Node, tainted: TaintMap): string | undefined {
  for (const pa of node.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    const text = pa.getText();
    if (tainted.has(text)) return text;
  }
  const identifiers = getIdentifierTexts(node);
  for (const name of tainted.keys()) {
    if (identifiers.has(name)) return name;
  }
  return undefined;
}

export function nodeContainsTainted(node: Node, tainted: Set<string>): boolean {
  const identifiers = getIdentifierTexts(node);
  for (const name of tainted) {
    if (identifiers.has(name)) return true;
  }
  return false;
}

function isSanitizerCall(node: Node, breakers: Set<string>): boolean {
  const call = node.asKind(SyntaxKind.CallExpression);
  if (!call) return false;
  const callee = call.getExpression().getText();
  const name = callee.split(".").pop() ?? callee;
  return breakers.has(name);
}

function getIdentifierTexts(node: Node): Set<string> {
  const names = new Set<string>();
  if (node.getKind() === SyntaxKind.Identifier) {
    names.add(node.getText());
  }
  node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .forEach((id) => names.add(id.getText()));
  return names;
}
