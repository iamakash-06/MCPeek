import type { ScanResult, AuditResult, Finding, Severity } from "../types.js";

const SEVERITY_ICON: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

export function toMarkdown(result: ScanResult): string {
  const { target, scannedAt, filesScanned, score, summary, findings } = result;
  const lines: string[] = [];

  lines.push(`# MCPeek Security Report`);
  lines.push(`\n**Target:** \`${target}\``);
  lines.push(`**Scanned:** ${new Date(scannedAt).toUTCString()}`);
  lines.push(`**Files scanned:** ${filesScanned}`);
  lines.push(`**Security score:** ${score}/100\n`);

  lines.push(`## Summary\n`);
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const count = summary[sev];
    if (count > 0) {
      lines.push(`| ${SEVERITY_ICON[sev]} ${capitalize(sev)} | ${count} |`);
    }
  }

  if (findings.length === 0) {
    lines.push(`\n## Findings\n\nNo issues found. ✅`);
    return lines.join("\n");
  }

  lines.push(`\n## Findings\n`);

  const bySeverity = groupBySeverity(findings);
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const group = bySeverity[sev];
    if (!group || group.length === 0) continue;

    lines.push(`### ${SEVERITY_ICON[sev]} ${capitalize(sev)} (${group.length})\n`);

    for (const f of group) {
      lines.push(`#### ${f.rule} — ${f.cwe}`);
      lines.push(`**File:** \`${relativePath(f.file, target)}\` line ${f.line}`);
      lines.push(`**Confidence:** ${f.confidence}`);
      lines.push(`\n${f.message}\n`);
      lines.push("```");
      lines.push(f.evidence);
      lines.push("```");
      lines.push(`\n> **Remediation:** ${f.remediation}\n`);
    }
  }

  return lines.join("\n");
}

export function auditToMarkdown(results: AuditResult[]): string {
  const lines: string[] = [];
  const date = new Date().toUTCString();

  lines.push(`# MCPeek: MCP Server Security Audit Report`);
  lines.push(`\n*Generated: ${date}*\n`);
  lines.push(`## Overview\n`);

  const totalFindings = results.reduce((s, r) => s + r.scan.findings.length, 0);
  const criticalCount = results.reduce((s, r) => s + r.scan.summary.critical, 0);
  const highCount = results.reduce((s, r) => s + r.scan.summary.high, 0);
  const serversWithCritical = results.filter((r) => r.scan.summary.critical > 0).length;
  const avgScore = Math.round(
    results.reduce((s, r) => s + r.scan.score, 0) / results.length
  );

  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Servers scanned | ${results.length} |`);
  lines.push(`| Total findings | ${totalFindings} |`);
  lines.push(`| Critical findings | ${criticalCount} |`);
  lines.push(`| High findings | ${highCount} |`);
  lines.push(`| Servers with critical issues | ${serversWithCritical} (${pct(serversWithCritical, results.length)}%) |`);
  lines.push(`| Average security score | ${avgScore}/100 |`);

  lines.push(`\n## Score Distribution\n`);
  lines.push(buildScoreHistogram(results));

  lines.push(`\n## Findings by Rule\n`);
  lines.push(buildRuleBreakdown(results));

  lines.push(`\n## Per-Server Results\n`);
  lines.push(`| # | Server | Score | Critical | High | Medium |`);
  lines.push(`|---|--------|-------|----------|------|--------|`);

  const sorted = [...results].sort((a, b) => a.scan.score - b.scan.score);
  sorted.forEach((r, i) => {
    const { name, url } = r.target;
    const { score, summary } = r.scan;
    lines.push(
      `| ${i + 1} | [${name}](${url}) | ${score}/100 | ${summary.critical} | ${summary.high} | ${summary.medium} |`
    );
  });

  lines.push(`\n---\n*Responsible disclosure: Critical and high findings were reported to maintainers prior to publication.*`);

  return lines.join("\n");
}

function buildScoreHistogram(results: AuditResult[]): string {
  const buckets = { "0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0 };
  for (const r of results) {
    const s = r.scan.score;
    if (s <= 20) buckets["0-20"]++;
    else if (s <= 40) buckets["21-40"]++;
    else if (s <= 60) buckets["41-60"]++;
    else if (s <= 80) buckets["61-80"]++;
    else buckets["81-100"]++;
  }
  const lines = ["| Score Range | Count | Bar |", "|-------------|-------|-----|"];
  for (const [range, count] of Object.entries(buckets)) {
    const bar = "█".repeat(count);
    lines.push(`| ${range} | ${count} | ${bar} |`);
  }
  return lines.join("\n");
}

function buildRuleBreakdown(results: AuditResult[]): string {
  const ruleCounts: Record<string, number> = {};
  for (const r of results) {
    for (const f of r.scan.findings) {
      ruleCounts[f.rule] = (ruleCounts[f.rule] ?? 0) + 1;
    }
  }
  const lines = ["| Rule | Occurrences | % Servers Affected |", "|------|-------------|---------------------|"];
  for (const [rule, count] of Object.entries(ruleCounts).sort((a, b) => b[1] - a[1])) {
    const affected = results.filter((r) =>
      r.scan.findings.some((f) => f.rule === rule)
    ).length;
    lines.push(`| \`${rule}\` | ${count} | ${pct(affected, results.length)}% |`);
  }
  return lines.join("\n");
}

function groupBySeverity(findings: Finding[]): Partial<Record<Severity, Finding[]>> {
  const out: Partial<Record<Severity, Finding[]>> = {};
  for (const f of findings) {
    (out[f.severity] ??= []).push(f);
  }
  return out;
}

function relativePath(filePath: string, target: string): string {
  return filePath.replace(target, "").replace(/^\//, "");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function pct(n: number, total: number): number {
  return total === 0 ? 0 : Math.round((n / total) * 100);
}
