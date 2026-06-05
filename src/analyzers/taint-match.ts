import { Node, SyntaxKind } from "ts-morph";
import { canonicalAccessKey } from "./taint-tracker.js";
import type { TaintEntry, TaintMap } from "./taint-tracker.js";

/**
 * Returns the most specific TaintMap entry reachable inside `node`:
 *   1. the node text itself (matches `opts.command` exactly)
 *   2. any property-access expression inside it (catches `opts.command` nested in a template)
 *   3. any element-access expression inside it (catches `opts["command"]`,
 *      normalised to the canonical dotted key)
 *   4. any bare identifier inside it (catches `command` from a destructured param)
 */
export function findTaintedReaching(
  node: Node,
  tainted: TaintMap
): TaintEntry | undefined {
  const direct = tainted.get(node.getText());
  if (direct) return direct;

  for (const pa of node.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    const hit = tainted.get(pa.getText());
    if (hit) return hit;
  }

  if (node.getKind() === SyntaxKind.ElementAccessExpression) {
    const hit = tainted.get(canonicalAccessKey(node)) ?? tainted.get(node.getText());
    if (hit) return hit;
  }
  for (const ea of node.getDescendantsOfKind(SyntaxKind.ElementAccessExpression)) {
    const hit = tainted.get(canonicalAccessKey(ea)) ?? tainted.get(ea.getText());
    if (hit) return hit;
  }

  if (node.getKind() === SyntaxKind.Identifier) {
    const hit = tainted.get(node.getText());
    if (hit) return hit;
  }
  for (const id of node.getDescendantsOfKind(SyntaxKind.Identifier)) {
    const hit = tainted.get(id.getText());
    if (hit) return hit;
  }
  return undefined;
}
