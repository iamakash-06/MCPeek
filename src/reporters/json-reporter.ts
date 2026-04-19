import type { ScanResult, AuditResult } from "../types.js";

export function toJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function auditToJSON(results: AuditResult[]): string {
  return JSON.stringify(
    {
      generatedAt: new Date().toISOString(),
      totalServers: results.length,
      results,
    },
    null,
    2
  );
}
