import { Node, SyntaxKind } from "ts-morph";

/**
 * Follows an Identifier through variable-declaration initializers — including
 * imports from other source files in the same Project — to the underlying
 * expression. Returns the input node unchanged if it isn't an Identifier or
 * can't be resolved.
 */
export function resolveSchemaDefinition(node: Node, depth = 0): Node {
  if (depth > 4) return node;
  const ident = node.asKind(SyntaxKind.Identifier);
  if (!ident) return node;
  try {
    for (const def of ident.getDefinitionNodes()) {
      const varDecl = def.asKind(SyntaxKind.VariableDeclaration);
      if (!varDecl) continue;
      const init = varDecl.getInitializer();
      if (init) return resolveSchemaDefinition(init, depth + 1);
    }
  } catch {
    // Unresolved identifier (e.g. import from a package not in the project).
  }
  return node;
}
