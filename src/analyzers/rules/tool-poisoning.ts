/**
 * Detects suspicious patterns in MCP tool names and descriptions —
 * the "line jumping" / tool-poisoning class catalogued by Trail of Bits.
 *
 * What we flag in the registration call:
 *   - Tool names with chars outside `^[a-zA-Z0-9_-]+$`
 *   - Hidden unicode in any tool string (RTLO U+202E, zero-width chars)
 *   - ANSI escape sequences in any tool string
 *   - Prompt-injection phrases in descriptions ("ignore previous", "[SYSTEM]", ...)
 *   - Description strings exceeding 2000 chars (likely instruction smuggling)
 *
 * One finding per registration call so multiple issues on the same line don't
 * get squashed by the rule-level dedup. Severity: high, confidence: medium.
 */

import { SourceFile, SyntaxKind, Node, CallExpression } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";

const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /ignore\s+(all\s+)?(prior|previous|preceding)\s+(instruction|prompt|message|direction)/i, label: "ignore-previous" },
  { pattern: /<\s*IMPORTANT\s*>/i, label: "important-tag" },
  { pattern: /<\s*SYSTEM\s*>/i, label: "system-tag" },
  { pattern: /\[\s*SYSTEM\s*\]/i, label: "system-bracket" },
  { pattern: /\byou\s+must\s+(always|never|first|now)\b/i, label: "you-must" },
  { pattern: /\bas\s+an\s+AI\b/i, label: "as-an-ai" },
  { pattern: /forget\s+(all|everything|previous|prior)/i, label: "forget-previous" },
  { pattern: /\bdisregard\s+(all|previous|prior|the)/i, label: "disregard" },
  { pattern: /override\s+(your|the|all|previous)\s+(instruction|rule|system)/i, label: "override-instructions" },
];

// Bidi controls (LRE/RLE/PDF/LRO/RLO + LRI/RLI/FSI/PDI + ALM),
// zero-width space/non-joiner/joiner, word joiner, BOM/ZWNBSP, Arabic letter mark.
const HIDDEN_UNICODE_RE = new RegExp(
  "[" +
    "\u202A-\u202E" +
    "\u200B-\u200D" +
    "\u2060" +
    "\uFEFF" +
    "\u061C" +
    "\u2066-\u2069" +
  "]"
);
// ESC (U+001B) followed by '[' — the start of an ANSI CSI sequence.
const ANSI_ESCAPE_RE = /\x1b\[/;
const VALID_TOOL_NAME = /^[a-zA-Z0-9_-]+$/;
const MAX_DESCRIPTION_LEN = 2000;

interface Issue {
  where: string;
  detail: string;
}

export function detectToolPoisoning(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);

  for (const call of calls) {
    const exprText = call.getExpression().getText();
    const isMCPRegistration =
      exprText.endsWith(".tool") ||
      exprText.endsWith(".addTool") ||
      exprText.endsWith(".registerTool") ||
      exprText === "server.tool";
    if (!isMCPRegistration) continue;

    const args = call.getArguments();
    if (args.length === 0) continue;

    const issues: Issue[] = [];

    // -------- Tool name (first arg, if string literal) --------
    const nameArg = args[0];
    const nameValue = stringLiteralValue(nameArg);
    if (nameValue !== undefined) {
      for (const detail of checkToolName(nameValue)) {
        issues.push({ where: `name "${truncate(nameValue, 60)}"`, detail });
      }
    }

    // -------- Description-like strings in remaining args --------
    for (const { value } of collectDescriptionStrings(call, nameArg)) {
      for (const detail of checkDescriptionString(value)) {
        issues.push({ where: "description", detail });
      }
    }

    if (issues.length === 0) continue;

    const lineNum = call.getStartLineNumber();
    const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());

    findings.push({
      rule: "mcp-tool-poisoning",
      severity: "high",
      cwe: "CWE-74",
      file: filePath,
      line: lineNum,
      column,
      message: `Suspicious content in MCP tool metadata: ${issues.map((i) => `${i.where} — ${i.detail}`).join("; ")}`,
      evidence: extractSnippet(sourceFile, lineNum, 3),
      remediation:
        "Strip prompt-injection phrases, hidden unicode (RTLO/zero-width), and ANSI escape sequences from tool names and descriptions. Constrain tool names to [a-zA-Z0-9_-]+. Cap descriptions at 2000 chars.",
      confidence: "medium",
    });
  }

  return findings;
}

function checkToolName(name: string): string[] {
  const details: string[] = [];
  if (!VALID_TOOL_NAME.test(name)) {
    if (HIDDEN_UNICODE_RE.test(name)) {
      details.push("contains hidden unicode (RTLO or zero-width chars)");
    } else if (ANSI_ESCAPE_RE.test(name)) {
      details.push("contains ANSI escape sequence");
    } else {
      details.push("contains characters outside [a-zA-Z0-9_-]");
    }
  }
  return details;
}

function checkDescriptionString(value: string): string[] {
  const details: string[] = [];
  if (value.length > MAX_DESCRIPTION_LEN) {
    details.push(`exceeds ${MAX_DESCRIPTION_LEN} chars (got ${value.length}) — possible instruction smuggling`);
  }
  if (HIDDEN_UNICODE_RE.test(value)) {
    details.push("contains hidden unicode (RTLO/zero-width)");
  }
  if (ANSI_ESCAPE_RE.test(value)) {
    details.push("contains ANSI escape sequence");
  }
  for (const { pattern, label } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(value)) {
      details.push(`contains prompt-injection phrase (${label})`);
    }
  }
  return details;
}

function collectDescriptionStrings(
  call: CallExpression,
  nameArg: Node
): Array<{ value: string }> {
  const results: Array<{ value: string }> = [];

  for (const arg of call.getArguments()) {
    if (arg === nameArg) continue;
    if (Node.isArrowFunction(arg) || Node.isFunctionExpression(arg)) continue;

    // Bare string arg (e.g. server.tool(name, description, schema, handler))
    const direct = stringLiteralValue(arg);
    if (direct !== undefined) {
      results.push({ value: direct });
      continue;
    }

    // Object literal arg with description/title properties
    const obj = arg.asKind(SyntaxKind.ObjectLiteralExpression);
    if (!obj) continue;

    for (const prop of obj.getProperties()) {
      const pa = prop.asKind(SyntaxKind.PropertyAssignment);
      if (!pa) continue;
      const propName = pa.getNameNode().getText().replace(/['"]/g, "");
      if (propName !== "description" && propName !== "title") continue;
      const init = pa.getInitializer();
      if (!init) continue;
      const value = stringLiteralValue(init);
      if (value !== undefined) results.push({ value });
    }
  }

  return results;
}

function stringLiteralValue(node: Node): string | undefined {
  const asStr = node.asKind(SyntaxKind.StringLiteral);
  if (asStr) return asStr.getLiteralValue();
  const asTpl = node.asKind(SyntaxKind.NoSubstitutionTemplateLiteral);
  if (asTpl) return asTpl.getLiteralValue();
  return undefined;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
