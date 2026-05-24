/**
 * Intra-function taint tracking for TypeScript MCP handler bodies.
 *
 * Given a set of source parameter names, walks all variable declarations
 * and assignments in a handler body and builds a taint map — every identifier
 * that carries tainted data, keyed to the full chain of aliases that led there.
 *
 * Returned map shape:
 *   "cmd"       → ["cmd (handler param)"]
 *   "command"   → ["cmd (handler param)", "command (line 3)"]
 *   "sanitized" → ["cmd (handler param)", "command (line 3)", "sanitized (line 5)"]
 *
 * Handles:
 *   const x = param                      → x is tainted
 *   const url = `https://host/${param}`  → url is tainted
 *   const path = baseDir + "/" + param   → path is tainted
 *   let out; out = buildCmd(param)       → out is tainted (conservative)
 */

import { Node, SyntaxKind } from "ts-morph";

export type TaintMap = Map<string, string[]>;

export function getTaintedNames(
  handlerBody: Node,
  paramNames: string[]
): TaintMap {
  // Seed: each param starts its own chain
  const tainted: TaintMap = new Map(
    paramNames.map((p) => [p, [`${p} (handler param)`]])
  );

  const decls = handlerBody.getDescendantsOfKind(SyntaxKind.VariableDeclaration);

  // Multiple passes: chains like (x = param; y = x; z = y) need pass ordering
  let changed = true;
  let passes = 0;
  while (changed && passes < 4) {
    changed = false;
    passes++;

    for (const decl of decls) {
      const init = decl.getInitializer();
      if (!init) continue;

      const nameNode = (decl as any).getNameNode?.();
      if (!nameNode) continue;

      if (nameNode.getKind() === SyntaxKind.Identifier) {
        // Simple: const x = taintedExpr
        const name = nameNode.getText();
        if (tainted.has(name)) continue;

        const match = findFirstTaintedIn(init, tainted);
        if (match) {
          const line = decl.getStartLineNumber();
          tainted.set(name, [...tainted.get(match)!, `${name} (line ${line})`]);
          changed = true;
        }
      } else if (nameNode.getKind() === SyntaxKind.ObjectBindingPattern) {
        // Destructuring: const { a, b: c } = taintedExpr
        // If the initializer is tainted, all bound names inherit the taint.
        const match = findFirstTaintedIn(init, tainted);
        if (!match) continue;

        const line = decl.getStartLineNumber();
        nameNode
          .getDescendantsOfKind(SyntaxKind.BindingElement)
          .forEach((el: any) => {
            const elName = el.getNameNode?.()?.getText();
            if (elName && !tainted.has(elName)) {
              tainted.set(elName, [...tainted.get(match)!, `${elName} (line ${line})`]);
              changed = true;
            }
          });
      }
    }
  }

  // Also catch imperative assignments: let x; x = param
  const assignments = handlerBody.getDescendantsOfKind(SyntaxKind.BinaryExpression);
  for (const assign of assignments) {
    if (assign.getOperatorToken().getText() !== "=") continue;
    const varName = assign.getLeft().getText().trim();
    if (tainted.has(varName)) continue;

    const match = findFirstTaintedIn(assign.getRight(), tainted);
    if (match) {
      const line = assign.getStartLineNumber();
      tainted.set(varName, [...tainted.get(match)!, `${varName} (line ${line})`]);
    }
  }

  return tainted;
}

/**
 * Returns the first tainted name whose text appears anywhere inside `node`,
 * or undefined if none match.
 */
export function findFirstTaintedIn(node: Node, tainted: TaintMap): string | undefined {
  const identifiers = getIdentifierTexts(node);
  for (const name of tainted.keys()) {
    if (identifiers.has(name)) return name;
  }
  return undefined;
}

/**
 * Returns true if the node's text contains any name from the tainted set.
 */
export function nodeContainsTainted(node: Node, tainted: Set<string>): boolean {
  const identifiers = getIdentifierTexts(node);
  for (const name of tainted) {
    if (identifiers.has(name)) return true;
  }
  return false;
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

