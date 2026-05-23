/**
 * Detects MCP tool schemas that declare typed parameters without any
 * size / range / format bounds — `z.string()`, `z.number()`, `z.array()`
 * with no chained constraint method.
 *
 * Agentic Control Plane's survey of 8,216 real MCP servers found 4,512
 * with unrefined params, the dominant class of weak validation in the wild.
 * The existing `mcp-weak-input-validation` rule only catches `z.any()` /
 * `z.unknown()`, missing all of them.
 *
 * Capped at 2 findings per file to keep score impact bounded (-10 max).
 */

import { SourceFile, SyntaxKind, Node } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";

const STRING_BOUND_METHODS = new Set([
  "min", "max", "length",
  "email", "url", "uuid", "cuid", "cuid2", "ulid", "nanoid", "base64",
  "regex", "startsWith", "endsWith", "includes",
  "datetime", "date", "time", "duration", "ip", "emoji",
  "refine", "superRefine",
]);

const NUMBER_BOUND_METHODS = new Set([
  "min", "max", "lt", "lte", "gt", "gte",
  "int", "positive", "negative", "nonnegative", "nonpositive",
  "finite", "safe", "multipleOf", "step",
  "refine", "superRefine",
]);

const ARRAY_BOUND_METHODS = new Set([
  "min", "max", "length", "nonempty",
  "refine", "superRefine",
]);

const MAX_FINDINGS_PER_FILE = 2;

export function detectWeakSchemaBounds(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    if (findings.length >= MAX_FINDINGS_PER_FILE) break;

    const expr = call.getExpression();
    const text = expr.getText();
    const isMCPRegistration =
      text.endsWith(".tool") ||
      text.endsWith(".addTool") ||
      text === "server.tool";
    if (!isMCPRegistration) continue;

    const args = call.getArguments();
    if (args.length < 3) continue;

    const schemaArg = args[1];
    const weakFields = findWeakFields(schemaArg);
    if (weakFields.length === 0) continue;

    const lineNum = call.getStartLineNumber();
    const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());

    findings.push({
      rule: "mcp-weak-schema-bounds",
      severity: "medium",
      cwe: "CWE-20",
      file: filePath,
      line: lineNum,
      column,
      message: `MCP tool schema declares parameters without size/range bounds: ${weakFields.join(", ")}`,
      evidence: extractSnippet(sourceFile, lineNum, 3),
      remediation:
        "Add bounds so the handler cannot be invoked with oversized or unconstrained input. e.g. z.string().min(1).max(1000), z.number().min(0).max(N), z.array(...).max(100).",
      confidence: "medium",
    });
  }

  return findings;
}

function findWeakFields(schemaNode: Node): string[] {
  // If the schema was passed by reference (`server.tool("x", schemaVar, handler)`),
  // follow the binding to its initializer before inspecting.
  schemaNode = resolveAliasChain(schemaNode);

  // Unwrap z.object({...}) → inner object literal
  const asCall = schemaNode.asKind(SyntaxKind.CallExpression);
  if (asCall) {
    const callee = asCall.getExpression().getText();
    if (callee === "z.object" || callee.endsWith(".object")) {
      const inner = asCall.getArguments()[0];
      if (inner) return findWeakFields(inner);
    }
    return [];
  }

  const obj = schemaNode.asKind(SyntaxKind.ObjectLiteralExpression);
  if (!obj) return [];

  const weak: string[] = [];
  for (const prop of obj.getProperties()) {
    const assignment = prop.asKind(SyntaxKind.PropertyAssignment);
    if (!assignment) continue;
    const fieldName = assignment.getNameNode().getText();
    const value = assignment.getInitializer();
    if (!value) continue;
    if (isWeakZodValue(value)) weak.push(fieldName);
  }
  return weak;
}

/**
 * Follows an Identifier to its variable-declaration initializer, repeating
 * to handle short alias chains (`const a = obj; const b = a;`). Returns the
 * original node unchanged if it isn't an Identifier or can't be resolved.
 */
function resolveAliasChain(node: Node, depth = 0): Node {
  if (depth > 4) return node;
  const ident = node.asKind(SyntaxKind.Identifier);
  if (!ident) return node;
  try {
    for (const def of ident.getDefinitionNodes()) {
      const varDecl = def.asKind(SyntaxKind.VariableDeclaration);
      if (!varDecl) continue;
      const init = varDecl.getInitializer();
      if (init) return resolveAliasChain(init, depth + 1);
    }
  } catch {
    // Unresolved identifier (e.g. import from a package not in the project) —
    // fall through and return the original node.
  }
  return node;
}

function isWeakZodValue(node: Node): boolean {
  const { baseType, methods } = analyzeZodChain(node);
  if (!baseType) return false;
  // z.any() / z.unknown() are handled by the existing weak-input-validation rule
  if (baseType === "any" || baseType === "unknown") return false;

  if (baseType === "string") return !hasAny(methods, STRING_BOUND_METHODS);
  if (baseType === "number" || baseType === "bigint")
    return !hasAny(methods, NUMBER_BOUND_METHODS);
  if (baseType === "array") return !hasAny(methods, ARRAY_BOUND_METHODS);
  return false;
}

function hasAny(arr: string[], set: Set<string>): boolean {
  return arr.some((m) => set.has(m));
}

/**
 * Walks a Zod chain inside-out and returns the base z.<type>() and the list
 * of subsequent method names. For `z.string().min(1).max(100)` returns
 * { baseType: "string", methods: ["min", "max"] }.
 */
function analyzeZodChain(node: Node): { baseType?: string; methods: string[] } {
  const methods: string[] = [];
  let current: Node = node;
  let baseType: string | undefined;

  while (true) {
    const call = current.asKind(SyntaxKind.CallExpression);
    if (!call) break;

    const pa = call.getExpression().asKind(SyntaxKind.PropertyAccessExpression);
    if (!pa) break;

    const methodName = pa.getName();
    const inner: Node = pa.getExpression();

    // Base of the chain: z.<methodName>(...)
    if (inner.getKind() === SyntaxKind.Identifier && inner.getText() === "z") {
      baseType = methodName;
      break;
    }

    methods.unshift(methodName);
    current = inner;
  }

  return { baseType, methods };
}
