import type { ScanResult, ScanOptions, Finding, Severity } from "./types.js";
import { analyzeTypeScript } from "./analyzers/ts-analyzer.js";
import { fetchRepo } from "./repo-fetcher.js";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

export async function scan(
  target: string,
  options: ScanOptions = {}
): Promise<ScanResult> {
  const { path, cleanup } = await fetchRepo(target);

  try {
    const { findings, filesScanned } = await analyzeTypeScript(path, options);

    const summary = buildSummary(findings);
    const score = calculateScore(findings);

    return {
      target,
      scannedAt: new Date().toISOString(),
      // Mark repos where we found no TypeScript files so callers can exclude
      // them from aggregate metrics — a score of 100 for a Go/Python repo is
      // misleading, not a clean bill of health.
      language: filesScanned === 0 ? "unknown" : "typescript",
      filesScanned,
      findings,
      score,
      summary,
    };
  } finally {
    cleanup();
  }
}

function buildSummary(
  findings: Finding[]
): ScanResult["summary"] {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}

function calculateScore(findings: Finding[]): number {
  const deduction = findings.reduce(
    (acc, f) => acc + (SEVERITY_WEIGHT[f.severity] ?? 0),
    0
  );
  return Math.max(0, 100 - deduction);
}

export function hasCriticalOrHighFindings(
  result: ScanResult,
  threshold: Severity
): boolean {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const thresholdIdx = order.indexOf(threshold);
  return result.findings.some(
    (f) => order.indexOf(f.severity) <= thresholdIdx
  );
}
