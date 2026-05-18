import type { ScanResult, AuditResult } from "../types.js";

export function toJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function auditToJSON(
  results: AuditResult[],
  meta?: { attempted: number; failed: number }
): string {
  return JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      attempted: meta?.attempted ?? results.length,
      scanned: results.length,
      failed: meta?.failed ?? 0,
      results,
    },
    null,
    2
  );
}
