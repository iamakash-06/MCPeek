import {
  CallExpression,
  Node,
  ParameterDeclaration,
  SourceFile,
  SyntaxKind,
} from "ts-morph";
import { getTaintedNames, TaintMap } from "./taint-tracker.js";
import { findTaintedReaching } from "./taint-match.js";

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

export interface ResolvedCallee {
  paramNames: string[];
  /** Positional, one entry per parameter: the identifier names it binds. */
  paramBindings: string[][];
  body: Node;
  file: string;
  fnName: string;
}

const LIBRARY_RECEIVERS = new Set([
  "express", "app", "router", "axios", "fetch", "http", "https",
  "fs", "path", "zod", "z", "server", "client", "db", "pool",
  "prisma", "knex", "sequelize", "console", "process",
  "Math", "JSON", "Object", "Array", "Promise", "Date", "URL",
]);

const MAX_PARAMS = 8;

/**
 * Resolves a single-hop call destination: a local function, a local arrow
 * binding, or an imported function / class method in another file in the
 * same Project. Returns undefined for library receivers, long-signature
 * functions, or unresolvable identifiers.
 */
export function resolveCallee(
  call: CallExpression,
  sourceFile: SourceFile
): ResolvedCallee | undefined {
  const exprText = call.getExpression().getText();
  const segments = exprText.split(".");

  if (segments.length === 1) {
    return resolveLocalOrImportedFunction(segments[0], sourceFile);
  }
  if (segments.length === 2) {
    const [receiver, method] = segments;
    if (LIBRARY_RECEIVERS.has(receiver)) return undefined;
    return (
      resolveNamespaceExportFunction(receiver, method, sourceFile) ??
      resolveImportedClassMethod(receiver, method, sourceFile)
    );
  }
  return undefined;
}

function resolveNamespaceExportFunction(
  receiver: string,
  method: string,
  sf: SourceFile
): ResolvedCallee | undefined {
  const target = followNamespaceImport(sf, receiver);
  if (!target) return undefined;

  const fn = target.getFunction(method);
  if (fn) {
    const body = fn.getBody();
    if (body) {
      return makeResolved(fn.getParameters(), body, target.getFilePath(), `${receiver}.${method}`);
    }
  }

  for (const v of target.getVariableDeclarations()) {
    if (v.getName() !== method) continue;
    const init = v.getInitializer();
    const arrow = init?.asKind(SyntaxKind.ArrowFunction);
    const fnExpr = init?.asKind(SyntaxKind.FunctionExpression);
    const f = arrow ?? fnExpr;
    if (!f) continue;
    const body = f.getBody();
    if (body) {
      return makeResolved(f.getParameters(), body, target.getFilePath(), `${receiver}.${method}`);
    }
  }
  return undefined;
}

function resolveLocalOrImportedFunction(
  name: string,
  sf: SourceFile
): ResolvedCallee | undefined {
  for (const fn of sf.getFunctions()) {
    if (fn.getName() !== name) continue;
    const body = fn.getBody();
    if (!body) continue;
    return makeResolved(fn.getParameters(), body, sf.getFilePath(), name);
  }

  for (const v of sf.getVariableDeclarations()) {
    if (v.getName() !== name) continue;
    const init = v.getInitializer();
    const arrow = init?.asKind(SyntaxKind.ArrowFunction);
    const fnExpr = init?.asKind(SyntaxKind.FunctionExpression);
    const fn = arrow ?? fnExpr;
    if (!fn) continue;
    const body = fn.getBody();
    if (!body) continue;
    return makeResolved(fn.getParameters(), body, sf.getFilePath(), name);
  }

  const target = followImport(sf, name);
  if (target) {
    const fn = target.getFunction(name);
    if (fn) {
      const body = fn.getBody();
      if (body) return makeResolved(fn.getParameters(), body, target.getFilePath(), name);
    }
  }
  return undefined;
}

function resolveImportedClassMethod(
  receiver: string,
  method: string,
  sf: SourceFile
): ResolvedCallee | undefined {
  const target = followImport(sf, receiver);
  if (!target) return undefined;
  const cls = target.getClass(receiver);
  if (!cls) return undefined;
  const m = cls.getMethod(method);
  if (!m) return undefined;
  const body = m.getBody();
  if (!body) return undefined;
  return makeResolved(m.getParameters(), body, target.getFilePath(), `${receiver}.${method}`);
}

function followImport(sf: SourceFile, name: string): SourceFile | undefined {
  for (const imp of sf.getImportDeclarations()) {
    const named = imp.getNamedImports().find((n) => (n.getAliasNode()?.getText() ?? n.getName()) === name);
    const isDefault = imp.getDefaultImport()?.getText() === name;
    if (!named && !isDefault) continue;
    const target = imp.getModuleSpecifierSourceFile();
    if (target) return target;
  }
  return undefined;
}

function followNamespaceImport(sf: SourceFile, name: string): SourceFile | undefined {
  for (const imp of sf.getImportDeclarations()) {
    if (imp.getNamespaceImport()?.getText() !== name) continue;
    const target = imp.getModuleSpecifierSourceFile();
    if (target) return target;
  }
  return undefined;
}

/**
 * For each call inside `handlerBody` whose tainted argument can be followed
 * one hop into a resolvable callee, invokes `visit` with the callee's body and
 * a fresh taint map seeded by the matching parameter (chain extended to span
 * the hop). Library receivers and oversized signatures are skipped; each
 * `${file}:${fnName}` is visited at most once.
 */
export function forEachTaintedCallTarget(
  handlerBody: Node,
  tainted: TaintMap,
  sourceFile: SourceFile,
  visit: (calleeBody: Node, calleeTainted: TaintMap, calleeFile: string) => void
): void {
  const visited = new Set<string>();
  for (const call of handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const args = call.getArguments();
    let callee: ResolvedCallee | undefined;
    let resolved = false;

    for (let argIdx = 0; argIdx < args.length; argIdx++) {
      const m = findTaintedReaching(args[argIdx], tainted);
      if (!m) continue;

      if (!resolved) {
        callee = resolveCallee(call, sourceFile);
        resolved = true;
      }
      if (!callee) break;

      const bindings = callee.paramBindings[argIdx];
      if (!bindings || bindings.length === 0) continue;

      // Key by argument identity so multiple tainted params are analysed separately.
      const key = `${callee.file}:${callee.fnName}:arg${argIdx}`;
      if (visited.has(key)) continue;
      visited.add(key);

      const calleeTainted = getTaintedNames(callee.body, bindings);
      for (const seedParam of bindings) {
        const seedEntry = calleeTainted.get(seedParam);
        if (seedEntry) {
          seedEntry.chain = [...m.chain, `${seedParam} (arg → ${callee.fnName})`];
        }
      }

      visit(callee.body, calleeTainted, callee.file);
    }
  }
}

function makeResolved(
  params: ParameterDeclaration[],
  body: Node,
  file: string,
  fnName: string
): ResolvedCallee | undefined {
  if (params.length > MAX_PARAMS) return undefined;
  const paramNames: string[] = [];
  const paramBindings: string[][] = [];
  for (const param of params) {
    const binding = param.getNameNode();
    paramNames.push(binding.getText());
    if (binding.getKind() === SyntaxKind.ObjectBindingPattern) {
      const names: string[] = [];
      binding
        .getDescendantsOfKind(SyntaxKind.BindingElement)
        .forEach((el) => {
          const n = el.getNameNode();
          if (n) names.push(n.getText());
        });
      paramBindings.push(names);
    } else {
      paramBindings.push([binding.getText()]);
    }
  }
  return { paramNames, paramBindings, body, file, fnName };
}
