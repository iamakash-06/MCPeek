import type { ScanResult, Finding, Severity } from "../types.js";

const SEVERITY_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

export function toSARIF(result: ScanResult): string {
  const rules = buildRuleDefinitions(result.findings);

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            version: "1.0.0",
            informationUri: "https://github.com/anthropics/mcp-audit",
            rules,
          },
        },
        results: result.findings.map((f) => buildResult(f, result.target)),
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: result.scannedAt,
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function buildRuleDefinitions(findings: Finding[]) {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    if (!seen.has(f.rule)) seen.set(f.rule, f);
  }

  return Array.from(seen.values()).map((f) => ({
    id: f.rule,
    name: ruleIdToName(f.rule),
    shortDescription: { text: f.message },
    fullDescription: { text: `${f.message}. ${f.remediation}` },
    helpUri: `https://cwe.mitre.org/data/definitions/${f.cwe.replace("CWE-", "")}.html`,
    properties: {
      tags: [f.cwe, "security", "mcp"],
      precision: f.confidence === "high" ? "high" : "medium",
      "security-severity": severityToScore(f.severity),
    },
    defaultConfiguration: {
      level: SEVERITY_LEVEL[f.severity],
    },
  }));
}

function buildResult(f: Finding, target: string) {
  const relPath = f.file.replace(target, "").replace(/^\//, "");

  return {
    ruleId: f.rule,
    level: SEVERITY_LEVEL[f.severity],
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: relPath },
          region: {
            startLine: f.line,
            startColumn: f.column,
          },
        },
      },
    ],
    properties: {
      cwe: f.cwe,
      confidence: f.confidence,
      remediation: f.remediation,
    },
  };
}

function ruleIdToName(ruleId: string): string {
  return ruleId
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("");
}

function severityToScore(severity: Severity): string {
  const scores: Record<Severity, string> = {
    critical: "9.0",
    high: "7.5",
    medium: "5.0",
    low: "2.5",
    info: "0.0",
  };
  return scores[severity];
}
