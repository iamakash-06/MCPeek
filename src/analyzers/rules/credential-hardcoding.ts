import { SourceFile, SyntaxKind, Node } from "ts-morph";
import type { Finding } from "../../types.js";
import { extractSnippet } from "../snippet.js";

export const CREDENTIAL_NAME_PATTERN =
  /\b(api[_-]?key|apikey|secret|token|password|passwd|auth[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|bearer)\b/i;

// Known credential prefixes (OpenAI, GitHub, Anthropic, Stripe, etc.)
export const CREDENTIAL_VALUE_PATTERNS = [
  /^sk-[a-zA-Z0-9]{20,}$/,
  /^ghp_[a-zA-Z0-9]{36}$/,
  /^ghs_[a-zA-Z0-9]{36}$/,
  /^github_pat_[a-zA-Z0-9_]{82}$/,
  /^sk-ant-[a-zA-Z0-9\-_]{80,}$/,
  /^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$/,
  /^AIza[0-9A-Za-z\-_]{35}$/,
  /^[a-f0-9]{32}$/,
];

export const MIN_SUSPICIOUS_LENGTH = 16;

// Values that look like credentials but are obviously placeholders
const PLACEHOLDER_PATTERNS = [
  /^(dummy|fake|test|mock|example|sample|placeholder|replace|changeme|change.me|your.key|your.token|your.secret|todo|fixme|xxx+|yyy+|zzz+)/i,
  /^<[^>]+>$/,           // <YOUR_KEY_HERE>
  /^\[.+\]$/,            // [REPLACE_ME]
  /will.be.replaced/i,
  /at.least.\d+.bits/i,  // "a-string-secret-at-least-256-bits-long"
  /^[a-z]+-[a-z]+-[a-z]+$/,  // test-client-secret, test-api-key style
];

export function detectHardcodedCredentials(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const declarations = sourceFile.getDescendantsOfKind(
    SyntaxKind.VariableDeclaration
  );

  for (const decl of declarations) {
    const name = decl.getName();
    if (!CREDENTIAL_NAME_PATTERN.test(name)) continue;

    const initializer = decl.getInitializer();
    if (!initializer) continue;

    if (isProcessEnvAccess(initializer)) continue;

    const kind = initializer.getKind();
    if (
      kind !== SyntaxKind.StringLiteral &&
      kind !== SyntaxKind.NoSubstitutionTemplateLiteral
    )
      continue;

    const value = initializer.getText().replace(/['"` ]/g, "");
    if (value.length < MIN_SUSPICIOUS_LENGTH) continue;
    if (isPlaceholder(value)) continue;

    const isKnownPattern = CREDENTIAL_VALUE_PATTERNS.some((p) =>
      p.test(value)
    );
    const looksLikeReal = value.length >= MIN_SUSPICIOUS_LENGTH && !/^[x*]+$/.test(value);

    if (!isKnownPattern && !looksLikeReal) continue;

    const lineNum = decl.getStartLineNumber();
    const redacted = value.slice(0, 6) + "..." + value.slice(-4);
    const { column } = sourceFile.getLineAndColumnAtPos(decl.getStart());

    findings.push({
      rule: "mcp-hardcoded-credential",
      severity: "high",
      cwe: "CWE-798",
      file: filePath,
      line: lineNum,
      column,
      message: `Hardcoded credential in variable "${name}" (value: ${redacted})`,
      evidence: extractSnippet(sourceFile, lineNum, 1),
      remediation:
        "Move credentials to environment variables: process.env.YOUR_KEY_NAME",
      confidence: isKnownPattern ? "high" : "medium",
    });
  }

  // Also scan for property assignments like { apiKey: "sk-..." }
  const propertyAssignments = sourceFile.getDescendantsOfKind(
    SyntaxKind.PropertyAssignment
  );

  for (const prop of propertyAssignments) {
    const name = prop.getName();
    if (!CREDENTIAL_NAME_PATTERN.test(name)) continue;

    const initializer = prop.getInitializer();
    if (!initializer) continue;
    if (isProcessEnvAccess(initializer)) continue;

    const kind = initializer.getKind();
    if (
      kind !== SyntaxKind.StringLiteral &&
      kind !== SyntaxKind.NoSubstitutionTemplateLiteral
    )
      continue;

    const value = initializer.getText().replace(/['"` ]/g, "");
    if (value.length < MIN_SUSPICIOUS_LENGTH) continue;
    if (isPlaceholder(value)) continue;

    const isKnownPattern = CREDENTIAL_VALUE_PATTERNS.some((p) =>
      p.test(value)
    );
    if (!isKnownPattern && value.length < 24) continue;

    const lineNum = prop.getStartLineNumber();
    const redacted = value.slice(0, 6) + "..." + value.slice(-4);
    const { column } = sourceFile.getLineAndColumnAtPos(prop.getStart());

    findings.push({
      rule: "mcp-hardcoded-credential",
      severity: "high",
      cwe: "CWE-798",
      file: filePath,
      line: lineNum,
      column,
      message: `Hardcoded credential in property "${name}" (value: ${redacted})`,
      evidence: extractSnippet(sourceFile, lineNum, 1),
      remediation:
        "Move credentials to environment variables: process.env.YOUR_KEY_NAME",
      confidence: isKnownPattern ? "high" : "medium",
    });
  }

  // Value-shape pass: catch known-prefix secrets bound to non-credential variable names
  // (e.g. `const ANTHROPIC = "sk-ant-..."`) that the name-based passes above miss.
  const reportedLines = new Set(findings.map((f) => f.line));
  const literals = [
    ...sourceFile.getDescendantsOfKind(SyntaxKind.StringLiteral),
    ...sourceFile.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral),
  ];
  for (const lit of literals) {
    const lineNum = lit.getStartLineNumber();
    if (reportedLines.has(lineNum)) continue;

    const value = lit.getText().replace(/^['"`]|['"`]$/g, "");
    if (value.length < MIN_SUSPICIOUS_LENGTH) continue;
    if (isPlaceholder(value)) continue;
    if (!CREDENTIAL_VALUE_PATTERNS.some((p) => p.test(value))) continue;

    const redacted = value.slice(0, 6) + "..." + value.slice(-4);
    const { column } = sourceFile.getLineAndColumnAtPos(lit.getStart());
    findings.push({
      rule: "mcp-hardcoded-credential",
      severity: "high",
      cwe: "CWE-798",
      file: filePath,
      line: lineNum,
      column,
      message: `Hardcoded credential literal (value: ${redacted})`,
      evidence: extractSnippet(sourceFile, lineNum, 1),
      remediation:
        "Move credentials to environment variables: process.env.YOUR_KEY_NAME",
      confidence: "high",
    });
    reportedLines.add(lineNum);
  }

  return findings;
}

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(value));
}

function isProcessEnvAccess(node: Node): boolean {
  const text = node.getText();
  return (
    text.startsWith("process.env") ||
    text.includes("process.env.") ||
    text.startsWith("env.")
  );
}
