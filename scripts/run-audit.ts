#!/usr/bin/env node
/**
 * Batch audit pipeline — scans all targets in targets/top-30.json
 * Usage: npx tsx scripts/run-audit.ts [--targets <file>] [--output <dir>]
 */
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { scan } from "../src/scanner.js";
import { auditToMarkdown } from "../src/reporters/markdown-reporter.js";
import { auditToJSON } from "../src/reporters/json-reporter.js";
import type { Target, AuditResult } from "../src/types.js";

const args = process.argv.slice(2);
const targetsFile = getArg(args, "--targets") ?? "targets/top-30.json";
const outputDir = getArg(args, "--output") ?? "results";

async function main() {
  const targets: Target[] = JSON.parse(readFileSync(targetsFile, "utf-8"));
  mkdirSync(outputDir, { recursive: true });

  console.log(`\nmcpeek batch scan`);
  console.log(`Targets: ${targets.length} | Output: ${outputDir}/\n`);

  const results: AuditResult[] = [];
  const failed: string[] = [];

  for (let i = 0; i < targets.length; i++) {
    const target = targets[i];
    const prefix = `[${String(i + 1).padStart(2, "0")}/${targets.length}]`;

    process.stdout.write(`${prefix} ${target.name} ... `);

    try {
      const scanResult = await scan(target.url);
      results.push({ target, scan: scanResult });

      const { score, summary } = scanResult;
      const flag = summary.critical > 0 ? " ⚠️  CRITICAL" : summary.high > 0 ? " ⚠️  HIGH" : "";
      console.log(`score=${score}/100 findings=${scanResult.findings.length}${flag}`);
    } catch (err) {
      const msg = (err as Error).message;
      console.log(`FAILED — ${msg}`);
      failed.push(`${target.name}: ${msg}`);
    }
  }

  // Write reports
  const mdPath = join(outputDir, "REPORT.md");
  const jsonPath = join(outputDir, "raw-results.json");

  writeFileSync(mdPath, auditToMarkdown(results), "utf-8");
  writeFileSync(jsonPath, auditToJSON(results), "utf-8");

  // Print aggregate stats
  const total = results.reduce((s, r) => s + r.scan.findings.length, 0);
  const critical = results.reduce((s, r) => s + r.scan.summary.critical, 0);
  const high = results.reduce((s, r) => s + r.scan.summary.high, 0);
  const avgScore = Math.round(
    results.reduce((s, r) => s + r.scan.score, 0) / (results.length || 1)
  );
  const withCritical = results.filter((r) => r.scan.summary.critical > 0).length;

  console.log("\n─────────────────────────────────────────");
  console.log(`Scanned:          ${results.length}/${targets.length} servers`);
  console.log(`Failed:           ${failed.length}`);
  console.log(`Total findings:   ${total}`);
  console.log(`Critical:         ${critical} (${pct(withCritical, results.length)}% of servers)`);
  console.log(`High:             ${high}`);
  console.log(`Average score:    ${avgScore}/100`);
  console.log("─────────────────────────────────────────");
  console.log(`\nReports written:`);
  console.log(`  ${mdPath}`);
  console.log(`  ${jsonPath}`);

  if (failed.length > 0) {
    console.log(`\nFailed targets:`);
    for (const f of failed) console.log(`  • ${f}`);
  }
}

function getArg(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
}

function pct(n: number, total: number): number {
  return total === 0 ? 0 : Math.round((n / total) * 100);
}

main().catch((err) => {
  console.error("Audit failed:", err);
  process.exit(1);
});
