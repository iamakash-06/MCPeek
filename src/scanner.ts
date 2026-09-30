import type { ScanResult, ScanOptions, Finding, Severity, Summary } from "./types.js";
import { analyzeTypeScript } from "./analyzers/ts-analyzer.js";
import { scanEnvFiles } from "./analyzers/env-scanner.js";
import { fetchRepo } from "./repo-fetcher.js";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

const CONFIDENCE_WEIGHT: Record<Finding["confidence"], number> = {
  high: 1,
  medium: 0.8,
  low: 0.5,
};

const MIGRATION_RULES = new Set(["mcp-session-keyed-state"]);

export function isMigrationFinding(f: Finding): boolean {
  return f.rule.startsWith("mcp-migration-") || MIGRATION_RULES.has(f.rule);
}

export async function scan(
  target: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const { path, cleanup } = await fetchRepo(target);

  try {
    const { findings: codeFindings, filesScanned, warnings, coverage } = await analyzeTypeScript(path, options);

    // Dotenv scanning is independent of the TS Program — a committed .env can
    // leak secrets even in a repo with zero TypeScript files (filesScanned: 0).
    const findings = [...codeFindings, ...scanEnvFiles(path)];

    const scored = findings.filter((f) => !f.context);
    const security = scored.filter((f) => !isMigrationFinding(f));
    const migration = scored.filter(isMigrationFinding);

    return {
      target,
      scannedAt: new Date().toISOString(),
      // Mark repos where we found no TypeScript files so callers can exclude
      // them from aggregate metrics — a score of 100 for a Go/Python repo is
      // misleading, not a clean bill of health.
      language: filesScanned === 0 ? "unknown" : "typescript",
      filesScanned,
      findings,
      warnings,
      coverage,
      score: calculateScore(security),
      summary: buildSummary(security),
      migration: { score: calculateScore(migration), summary: buildSummary(migration) },
    };
  } finally {
    cleanup();
  }
}

function buildSummary(findings: Finding[]): Summary {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}

function calculateScore(findings: Finding[]): number {
  const deduction = findings.reduce(
    (acc, f) => acc + (SEVERITY_WEIGHT[f.severity] ?? 0) * CONFIDENCE_WEIGHT[f.confidence],
    0
  );
  return Math.max(0, Math.round(100 - deduction));
}

export function hasCriticalOrHighFindings(
  result: ScanResult,
  threshold: Severity
): boolean {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const thresholdIdx = order.indexOf(threshold);
  return result.findings.some(
    (f) => !f.context && !isMigrationFinding(f) && order.indexOf(f.severity) <= thresholdIdx
  );
}
