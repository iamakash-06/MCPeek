/**
 * Shared utility: locates MCP tool handler registrations in a TypeScript source file.
 *
 * Covers the three main calling conventions in the wild:
 *   server.tool(name, handler)           — no schema
 *   server.tool(name, schema, handler)   — with Zod schema
 *   server.setRequestHandler(...)        — low-level SDK API
 *   server.addTool(...)                  — community wrapper libraries
 */

import { SourceFile, SyntaxKind, Node } from "ts-morph";

export interface MCPToolHandler {
  paramNames: string[];
  handlerBody: Node | undefined;
}

export function findMCPToolHandlers(sourceFile: SourceFile): MCPToolHandler[] {
  const results: MCPToolHandler[] = [];
  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const expr = call.getExpression();
    const text = expr.getText();

    const isMCPRegistration =
      text.endsWith(".tool") ||
      text.endsWith(".setRequestHandler") ||
      text.endsWith(".addTool") ||
      text === "server.tool" ||
      text === "server.setRequestHandler";

    if (!isMCPRegistration) continue;

    const args = call.getArguments();
    if (args.length < 2) continue;

    // server.tool(name, handler)          → args[1] is handler
    // server.tool(name, schema, handler)  → args[2] is handler
    const lastArg = args[args.length - 1];
    const handlerFn =
      lastArg.getKind() === SyntaxKind.ArrowFunction ||
      lastArg.getKind() === SyntaxKind.FunctionExpression
        ? lastArg
        : undefined;

    if (!handlerFn) continue;

    // MCP handlers receive a single destructured input object as their first param.
    // Slice to 1 to avoid treating the SDK context object as user-controlled input.
    const params = handlerFn.getDescendantsOfKind(SyntaxKind.Parameter);
    const paramNames: string[] = [];

    for (const param of params.slice(0, 1)) {
      const binding = param.getNameNode();
      if (binding.getKind() === SyntaxKind.ObjectBindingPattern) {
        binding
          .getDescendantsOfKind(SyntaxKind.BindingElement)
          .forEach((el) => {
            const nameNode = el.getNameNode();
            if (nameNode) paramNames.push(nameNode.getText());
          });
      } else {
        paramNames.push(binding.getText());
      }
    }

    const body =
      handlerFn.getDescendantsOfKind(SyntaxKind.Block)[0] ?? handlerFn;

    results.push({ paramNames, handlerBody: body });
  }

  return results;
}
