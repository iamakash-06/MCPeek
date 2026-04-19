import { SourceFile, SyntaxKind, VariableDeclaration, Node } from "ts-morph";
import type { Finding } from "../../types.js";

const CREDENTIAL_NAME_PATTERN =
  /\b(api[_-]?key|apikey|secret|token|password|passwd|auth[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|bearer)\b/i;

// Known credential prefixes (OpenAI, GitHub, Anthropic, Stripe, etc.)
const CREDENTIAL_VALUE_PATTERNS = [
  /^sk-[a-zA-Z0-9]{20,}$/,
  /^ghp_[a-zA-Z0-9]{36}$/,
  /^ghs_[a-zA-Z0-9]{36}$/,
  /^github_pat_[a-zA-Z0-9_]{82}$/,
  /^sk-ant-[a-zA-Z0-9\-_]{80,}$/,
  /^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$/,
  /^AIza[0-9A-Za-z\-_]{35}$/,
  /^[a-f0-9]{32}$/,
];

const MIN_SUSPICIOUS_LENGTH = 16;

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

    const isKnownPattern = CREDENTIAL_VALUE_PATTERNS.some((p) =>
      p.test(value)
    );
    const looksLikeReal = value.length >= MIN_SUSPICIOUS_LENGTH && !/^[x*]+$/.test(value);

    if (!isKnownPattern && !looksLikeReal) continue;

    const lineNum = decl.getStartLineNumber();
    const redacted = value.slice(0, 6) + "..." + value.slice(-4);

    findings.push({
      rule: "mcp-hardcoded-credential",
      severity: "high",
      cwe: "CWE-798",
      file: filePath,
      line: lineNum,
      column: 1,
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

    const isKnownPattern = CREDENTIAL_VALUE_PATTERNS.some((p) =>
      p.test(value)
    );
    if (!isKnownPattern && value.length < 24) continue;

    const lineNum = prop.getStartLineNumber();
    const redacted = value.slice(0, 6) + "..." + value.slice(-4);

    findings.push({
      rule: "mcp-hardcoded-credential",
      severity: "high",
      cwe: "CWE-798",
      file: filePath,
      line: lineNum,
      column: 1,
      message: `Hardcoded credential in property "${name}" (value: ${redacted})`,
      evidence: extractSnippet(sourceFile, lineNum, 1),
      remediation:
        "Move credentials to environment variables: process.env.YOUR_KEY_NAME",
      confidence: isKnownPattern ? "high" : "medium",
    });
  }

  return findings;
}

function isProcessEnvAccess(node: Node): boolean {
  const text = node.getText();
  return (
    text.startsWith("process.env") ||
    text.includes("process.env.") ||
    text.startsWith("env.")
  );
}

function extractSnippet(
  sourceFile: SourceFile,
  lineNum: number,
  context: number
): string {
  const lines = sourceFile.getFullText().split("\n");
  const start = Math.max(0, lineNum - context - 1);
  const end = Math.min(lines.length, lineNum + context);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join("\n");
}
