/**
 * Shared utility: locates MCP tool handler registrations in a TypeScript source file.
 *
 * Covers the three main calling conventions in the wild:
 *   server.tool(name, handler)           — no schema
 *   server.tool(name, schema, handler)   — with Zod schema
 *   server.setRequestHandler(...)        — low-level SDK API
 *   server.addTool(...)                  — community wrapper libraries
 */

import {
  SourceFile,
  SyntaxKind,
  Node,
  ArrowFunction,
  FunctionExpression,
  FunctionDeclaration,
  BindingElement,
} from "ts-morph";

export interface MCPToolHandler {
  paramNames: string[];
  handlerBody: Node | undefined;
}

export interface HandlerScanOptions {
  /**
   * Extra function names that register MCP tools via a project-local wrapper,
   * e.g. `registerMyTool("run", handler)`. Without these, custom wrappers are
   * invisible to taint analysis (limitation L7). Matched against the full
   * callee text and its last dotted segment.
   */
  extraRegistrations?: string[];
  /**
   * Treat the handler's second parameter (the SDK context object) as
   * attacker-controlled too (limitation L6). Off by default — only useful when a
   * custom wrapper injects user data into context, and it raises false positives
   * on normal SDK context usage.
   */
  taintContextParam?: boolean;
}

type HandlerFn = ArrowFunction | FunctionExpression | FunctionDeclaration;

function resolveHandlerFunction(node: Node): HandlerFn | undefined {
  if (Node.isArrowFunction(node) || Node.isFunctionExpression(node)) return node;

  const ident = node.asKind(SyntaxKind.Identifier);
  if (!ident) return undefined;

  try {
    for (const def of ident.getDefinitionNodes()) {
      if (Node.isFunctionDeclaration(def)) return def;
      const varDecl = def.asKind(SyntaxKind.VariableDeclaration);
      const init = varDecl?.getInitializer();
      if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) {
        return init;
      }
    }
  } catch {
    // unresolved identifier — fall through
  }
  return undefined;
}

function isMCPRegistration(text: string, extraRegistrations: string[]): boolean {
  if (
    text.endsWith(".tool") ||
    text.endsWith(".setRequestHandler") ||
    text.endsWith(".addTool") ||
    text === "server.tool" ||
    text === "server.setRequestHandler"
  ) {
    return true;
  }
  const lastSegment = text.split(".").pop() ?? text;
  return extraRegistrations.some((name) => text === name || lastSegment === name);
}

export function findMCPToolHandlers(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): MCPToolHandler[] {
  const results: MCPToolHandler[] = [];
  const extraRegistrations = options.extraRegistrations ?? [];
  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const expr = call.getExpression();
    const text = expr.getText();

    if (!isMCPRegistration(text, extraRegistrations)) continue;

    const args = call.getArguments();
    if (args.length < 2) continue;

    // server.tool(name, handler)          → args[1] is handler
    // server.tool(name, schema, handler)  → args[2] is handler
    const lastArg = args[args.length - 1];
    const handlerFn = resolveHandlerFunction(lastArg);

    if (!handlerFn) continue;

    // MCP handlers receive a single destructured input object as their first param.
    // Slice to 1 to avoid treating the SDK context object as user-controlled input,
    // unless taintContextParam opts in to modeling the second param too (L6).
    const params = handlerFn.getParameters();
    const paramNames: string[] = [];
    const paramLimit = options.taintContextParam ? 2 : 1;

    for (const param of params.slice(0, paramLimit)) {
      const binding = param.getNameNode();
      if (binding.getKind() === SyntaxKind.ObjectBindingPattern) {
        binding
          .getDescendantsOfKind(SyntaxKind.BindingElement)
          .forEach((el: BindingElement) => {
            const nameNode = el.getNameNode();
            if (nameNode) paramNames.push(nameNode.getText());
          });
      } else {
        paramNames.push(binding.getText());
      }
    }

    const body = handlerFn.getBody();
    const handlerBody =
      body && body.getKind() === SyntaxKind.Block ? body : body ?? handlerFn;

    results.push({ paramNames, handlerBody });
  }

  return results;
}
