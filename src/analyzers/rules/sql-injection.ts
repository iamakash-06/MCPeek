/**
 * Detects MCP tool handler parameters flowing into raw SQL queries
 * without parameterisation. CWE-89, severity critical.
 *
 * Two confidence tiers:
 *   - Template literal (or tagged template) into a SQL sink → always flag.
 *     String interpolation into a query is the classic injection shape; no
 *     popular ORM emits this pattern when used safely.
 *   - Plain first arg (concatenation, variable, etc.) into a SQL sink →
 *     only flag if the receiver looks like a DB handle (db/pool/client/
 *     knex/sequelize/prisma/pg/conn/...).
 *
 * Sinks: `query`, `raw`, `$queryRaw`, `$queryRawUnsafe`, `$executeRaw`,
 *        `$executeRawUnsafe`, `execute`, `executeQuery`, `runQuery`.
 */

import { SourceFile, SyntaxKind, Node, Identifier } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames, TaintMap } from "../taint-tracker.js";
import { findMCPToolHandlers } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

const SQL_SINKS = new Set([
  "query",
  "raw",
  "$queryRaw",
  "$queryRawUnsafe",
  "$executeRaw",
  "$executeRawUnsafe",
  "execute",
  "executeQuery",
  "runQuery",
]);

const DB_RECEIVER_PATTERN =
  /\b(db|pool|client|knex|sequelize|prisma|pg|conn|connection|sqlite|sqlite3|mysql|postgres|dataSource|datasource|repo|repository|trx|transaction)\b/i;

export function detectSqlInjection(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);

    for (const call of handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const finding = checkCall(call, tainted, sourceFile, filePath);
      if (finding) findings.push(finding);
    }

    for (const tagged of handlerBody.getDescendantsOfKind(SyntaxKind.TaggedTemplateExpression)) {
      const finding = checkTaggedTemplate(tagged, tainted, sourceFile, filePath);
      if (finding) findings.push(finding);
    }
  }

  return findings;
}

function checkCall(
  call: Node,
  tainted: TaintMap,
  sourceFile: SourceFile,
  filePath: string
): Finding | undefined {
  const callExpr = call.asKind(SyntaxKind.CallExpression);
  if (!callExpr) return undefined;

  const callText = callExpr.getExpression().getText();
  const funcName = callText.split(".").pop() ?? callText;
  if (!SQL_SINKS.has(funcName)) return undefined;

  const args = callExpr.getArguments();
  if (args.length === 0) return undefined;

  const firstArg = args[0];
  const matchedName = [...tainted.keys()].find((p) => containsIdentifier(firstArg, p));
  if (matchedName === undefined) return undefined;

  const kind = firstArg.getKind();
  const isTemplate =
    kind === SyntaxKind.TemplateExpression ||
    kind === SyntaxKind.NoSubstitutionTemplateLiteral;

  // Template literals into a SQL sink are unsafe regardless of receiver.
  // Other shapes (concatenation, variable, string literal that somehow
  // matches a tainted name) require a DB-like receiver to flag.
  if (!isTemplate && !DB_RECEIVER_PATTERN.test(callText)) return undefined;

  return buildFinding(callExpr, funcName, matchedName, tainted, sourceFile, filePath);
}

function checkTaggedTemplate(
  tagged: Node,
  tainted: TaintMap,
  sourceFile: SourceFile,
  filePath: string
): Finding | undefined {
  const node = tagged.asKind(SyntaxKind.TaggedTemplateExpression);
  if (!node) return undefined;

  const tagText = node.getTag().getText();
  const funcName = tagText.split(".").pop() ?? tagText;
  if (!SQL_SINKS.has(funcName)) return undefined;

  // Prisma's $queryRaw / $executeRaw automatically parameterise interpolated
  // values when used as tagged templates. Only the *Unsafe variants are
  // dangerous in this position.
  if (funcName === "$queryRaw" || funcName === "$executeRaw") return undefined;

  const template = node.getTemplate();
  const matchedName = [...tainted.keys()].find((p) => containsIdentifier(template, p));
  if (matchedName === undefined) return undefined;

  return buildFinding(node, funcName, matchedName, tainted, sourceFile, filePath);
}

function buildFinding(
  node: Node,
  funcName: string,
  matchedName: string,
  tainted: TaintMap,
  sourceFile: SourceFile,
  filePath: string
): Finding {
  const lineNum = node.getStartLineNumber();
  const chain = tainted.get(matchedName)!;
  const { column } = sourceFile.getLineAndColumnAtPos(node.getStart());

  return {
    rule: "mcp-sql-injection",
    severity: "critical",
    cwe: "CWE-89",
    file: filePath,
    line: lineNum,
    column,
    message: `User-controlled input flows into ${funcName}() as raw SQL without parameterisation`,
    evidence: extractSnippet(sourceFile, lineNum, 3),
    remediation:
      "Use parameterised queries: db.query('SELECT * FROM t WHERE id = ?', [userInput]). For Prisma, prefer the ORM API (findUnique, findMany) over $queryRaw, or pass interpolated values through tagged-template parameters so Prisma escapes them.",
    confidence: "high",
    taintChain: [...chain, `${funcName}() (line ${lineNum})`],
  };
}

function containsIdentifier(node: Node, name: string): boolean {
  if (node.getKind() === SyntaxKind.Identifier && node.getText() === name) {
    return true;
  }
  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((id: Identifier) => id.getText() === name);
}
