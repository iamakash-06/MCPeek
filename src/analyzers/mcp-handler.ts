/**
 * Shared utility: locates MCP tool handler registrations in a TypeScript source file.
 *
 * Covers the three main calling conventions in the wild:
 *   server.tool(name, handler)           — no schema
 *   server.tool(name, schema, handler)   — with Zod schema
 *   server.setRequestHandler(...)        — low-level SDK API
 *   server.addTool(...)                  — community wrapper libraries
 *   server.registerTool(name, config, handler) — v2 SDK
 */

import {
  SourceFile,
  SyntaxKind,
  Node,
  ArrowFunction,
  FunctionExpression,
  FunctionDeclaration,
  MethodDeclaration,
  BindingElement,
  CallExpression,
} from "ts-morph";
import { resolveSchemaDefinition } from "./cross-file.js";

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

type HandlerFn = ArrowFunction | FunctionExpression | FunctionDeclaration | MethodDeclaration;

const MAX_RESOLVE_DEPTH = 3;

function unwrap(node: Node): Node {
  while (
    Node.isParenthesizedExpression(node) ||
    Node.isAsExpression(node) ||
    Node.isNonNullExpression(node) ||
    Node.isTypeAssertion(node)
  ) {
    node = node.getExpression();
  }
  return node;
}

function asFunction(node: Node | undefined): HandlerFn | undefined {
  if (!node) return undefined;
  return Node.isArrowFunction(node) ||
    Node.isFunctionExpression(node) ||
    Node.isFunctionDeclaration(node) ||
    Node.isMethodDeclaration(node)
    ? node
    : undefined;
}

function definitionInitializers(ident: Node): Node[] {
  const out: Node[] = [];
  try {
    for (const def of ident.asKindOrThrow(SyntaxKind.Identifier).getDefinitionNodes()) {
      if (Node.isFunctionDeclaration(def)) out.push(def);
      const init = def.asKind(SyntaxKind.VariableDeclaration)?.getInitializer();
      if (init) out.push(init);
    }
  } catch {
    // unresolved identifier
  }
  return out;
}

function returnedFunction(fn: HandlerFn, depth: number): HandlerFn | undefined {
  const body = fn.getBody();
  if (!body) return undefined;
  const exprs = Node.isBlock(body)
    ? body
        .getDescendantsOfKind(SyntaxKind.ReturnStatement)
        .filter((r) => r.getFirstAncestor((a) => asFunction(a) !== undefined) === fn)
        .flatMap((r) => (r.getExpression() ? [r.getExpression()!] : []))
    : [body];
  for (const expr of exprs) {
    const found = resolveHandlerFunction(expr, depth + 1);
    if (found) return found;
  }
  return undefined;
}

function resolveHandlerFunction(node: Node, depth = 0): HandlerFn | undefined {
  if (depth > MAX_RESOLVE_DEPTH) return undefined;
  node = unwrap(node);

  const direct = asFunction(node);
  if (direct) return direct;

  if (Node.isIdentifier(node)) {
    for (const init of definitionInitializers(node)) {
      const found = resolveHandlerFunction(init, depth + 1);
      if (found) return found;
    }
    return undefined;
  }

  // Handler factory: createHandler(cfg) returns the function that is registered.
  if (Node.isCallExpression(node)) {
    const callee = unwrap(node.getExpression());
    if (!Node.isIdentifier(callee)) return undefined;
    for (const init of definitionInitializers(callee)) {
      const factory = asFunction(unwrap(init));
      const returned = factory && returnedFunction(factory, depth);
      if (returned) return returned;
    }
  }
  return undefined;
}

const CONFIG_REGISTRATIONS: Record<string, { config: number; key: string }> = {
  registerTool: { config: 1, key: "inputSchema" },
  registerPrompt: { config: 1, key: "argsSchema" },
  registerAppTool: { config: 2, key: "inputSchema" },
};

const RESOURCE_REGISTRATIONS = new Set(["registerResource", "registerAppResource"]);

function lastSegment(text: string): string {
  return text.split(".").pop() ?? text;
}

export function getRegisterToolInputSchema(call: CallExpression): Node | undefined {
  const spec = CONFIG_REGISTRATIONS[lastSegment(call.getExpression().getText())];
  const config = spec && call.getArguments()[spec.config];
  if (!config) return undefined;
  const obj = resolveSchemaDefinition(config).asKind(SyntaxKind.ObjectLiteralExpression);
  const prop = obj?.getProperty(spec.key);
  if (!prop) return undefined;
  if (Node.isPropertyAssignment(prop)) return prop.getInitializer();
  if (Node.isShorthandPropertyAssignment(prop)) return prop.getNameNode();
  return undefined;
}

function isMCPRegistration(text: string, extraRegistrations: string[]): boolean {
  if (
    text.endsWith(".tool") ||
    text.endsWith(".setRequestHandler") ||
    text.endsWith(".addTool") ||
    text.endsWith(".registerTool") ||
    text === "server.tool" ||
    lastSegment(text) in CONFIG_REGISTRATIONS ||
    RESOURCE_REGISTRATIONS.has(lastSegment(text)) ||
    text === "server.setRequestHandler"
  ) {
    return true;
  }
  return extraRegistrations.some((name) => text === name || lastSegment(text) === name);
}

function toHandler(fn: HandlerFn, paramLimit: number, noInput: boolean): MCPToolHandler {
  const paramNames: string[] = [];
  for (const param of noInput ? [] : fn.getParameters().slice(0, paramLimit)) {
    const binding = param.getNameNode();
    if (binding.getKind() === SyntaxKind.ObjectBindingPattern) {
      binding.getDescendantsOfKind(SyntaxKind.BindingElement).forEach((el: BindingElement) => {
        const nameNode = el.getNameNode();
        if (nameNode) paramNames.push(nameNode.getText());
      });
    } else {
      paramNames.push(binding.getText());
    }
  }
  const body = fn.getBody();
  return { paramNames, handlerBody: body ?? fn };
}

const DEFINITION_SCHEMA_KEYS = ["inputSchema", "parameters"];
const DEFINITION_HANDLER_KEYS = ["handler", "execute", "cb", "callback"];

function findToolDefinitions(
  sourceFile: SourceFile,
  seen: Set<Node>,
  paramLimit: number
): MCPToolHandler[] {
  const results: MCPToolHandler[] = [];
  for (const obj of sourceFile.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
    const hasSchema = DEFINITION_SCHEMA_KEYS.some((k) => obj.getProperty(k));
    for (const key of DEFINITION_HANDLER_KEYS) {
      const prop = obj.getProperty(key);
      const fn = Node.isPropertyAssignment(prop ?? obj)
        ? asFunction(prop?.asKind(SyntaxKind.PropertyAssignment)?.getInitializer())
        : undefined;
      const handlerFn = fn ?? asFunction(prop);
      if (!handlerFn || seen.has(handlerFn)) continue;
      const looksLikeTool = hasSchema || (key === "cb" && obj.getProperty("name") && obj.getProperty("description"));
      if (!looksLikeTool) continue;
      seen.add(handlerFn);
      results.push(toHandler(handlerFn, paramLimit, !hasSchema));
    }
  }
  return results;
}

export function findMCPToolHandlers(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): MCPToolHandler[] {
  const results: MCPToolHandler[] = [];
  const seen = new Set<Node>();
  const extraRegistrations = options.extraRegistrations ?? [];
  const baseLimit = options.taintContextParam ? 2 : 1;

  for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const text = call.getExpression().getText();
    if (!isMCPRegistration(text, extraRegistrations)) continue;

    const args = call.getArguments();
    if (args.length < 2) continue;

    // server.tool(name, handler) → args[1]; server.tool(name, schema, handler) → args[2]
    const lastArg = args[args.length - 1];
    const handlerFn = resolveHandlerFunction(lastArg);
    if (!handlerFn) continue;
    seen.add(handlerFn);

    // The SDK context (second param) stays untainted unless taintContextParam opts in (L6).
    // v2 registerTool / registerPrompt without a schema call the handler with (extra) only.
    const spec = CONFIG_REGISTRATIONS[lastSegment(text)];
    const noInput =
      !!spec &&
      resolveSchemaDefinition(args[spec.config] ?? lastArg).isKind(SyntaxKind.ObjectLiteralExpression) &&
      !getRegisterToolInputSchema(call);
    const paramLimit = RESOURCE_REGISTRATIONS.has(lastSegment(text)) ? 2 : baseLimit;
    results.push(toHandler(handlerFn, paramLimit, noInput));
  }

  results.push(...findToolDefinitions(sourceFile, seen, baseLimit));
  return results;
}
