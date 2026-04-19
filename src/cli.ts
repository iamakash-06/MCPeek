#!/usr/bin/env node
import { Command } from "commander";
import { writeFileSync, mkdirSync } from "fs";
import { dirname, join } from "path";
import { scan, hasCriticalOrHighFindings } from "./scanner.js";
import { toJSON, auditToJSON } from "./reporters/json-reporter.js";
import { toMarkdown, auditToMarkdown } from "./reporters/markdown-reporter.js";
import { toSARIF } from "./reporters/sarif-reporter.js";
import type { OutputFormat, Severity, Target, AuditResult } from "./types.js";

const program = new Command();

program
  .name("mcpeek")
  .description("Source-code security scanner for MCP server implementations")
  .version("1.0.0");

// ── scan command ────────────────────────────────────────────────────────────
program
  .command("scan <target>")
  .description("Scan an MCP server (GitHub URL or local path)")
  .option("-f, --format <format>", "Output format: json | markdown | sarif", "markdown")
  .option("-o, --output <file>", "Write output to file instead of stdout")
  .option("--rules <rules>", "Comma-separated list of rules to run")
  .option("--ci", "CI mode: exit with code 1 if issues found")
  .option("--fail-on <severity>", "Minimum severity to trigger CI failure (critical|high|medium|low)", "high")
  .action(async (target: string, opts) => {
    console.error(`[mcpeek] Scanning ${target}...`);

    const rules = opts.rules?.split(",").map((r: string) => r.trim());
    const result = await scan(target, { rules });

    const format = opts.format as OutputFormat;
    const output = formatResult(result, format);

    if (opts.output) {
      mkdirSync(dirname(opts.output), { recursive: true });
      writeFileSync(opts.output, output, "utf-8");
      console.error(`[mcpeek] Report written to ${opts.output}`);
    } else {
      process.stdout.write(output + "\n");
    }

    printSummary(result);

    if (opts.ci) {
      const threshold = (opts.failOn ?? "high") as Severity;
      if (hasCriticalOrHighFindings(result, threshold)) {
        process.exit(1);
      }
    }
  });

// ── audit command ───────────────────────────────────────────────────────────
program
  .command("audit")
  .description("Run a batch audit against a list of targets")
  .requiredOption("--targets <file>", "Path to targets JSON file")
  .option("--output <dir>", "Directory for output files", "results")
  .option("-f, --format <format>", "Output format: json | markdown", "markdown")
  .option("--rules <rules>", "Comma-separated list of rules to run")
  .action(async (opts) => {
    const { readFileSync } = await import("fs");
    const targets: Target[] = JSON.parse(readFileSync(opts.targets, "utf-8"));

    console.error(`[mcpeek] Starting audit of ${targets.length} servers...`);
    mkdirSync(opts.output, { recursive: true });

    const results: AuditResult[] = [];
    const rules = opts.rules?.split(",").map((r: string) => r.trim());

    for (let i = 0; i < targets.length; i++) {
      const target = targets[i];
      console.error(`[${i + 1}/${targets.length}] ${target.name}`);

      try {
        const scanResult = await scan(target.url, { rules });
        results.push({ target, scan: scanResult });
        console.error(
          `  ✓ score=${scanResult.score} findings=${scanResult.findings.length}`
        );
      } catch (err) {
        console.error(`  ✗ Failed: ${(err as Error).message}`);
      }
    }

    // Write combined report
    const mdReport = auditToMarkdown(results);
    writeFileSync(join(opts.output, "REPORT.md"), mdReport, "utf-8");

    const jsonReport = auditToJSON(results);
    writeFileSync(join(opts.output, "raw-results.json"), jsonReport, "utf-8");

    console.error(`\n[mcpeek] Audit complete. Reports written to ${opts.output}/`);
    printAuditSummary(results);
  });

program.parse();

// ── helpers ─────────────────────────────────────────────────────────────────

function formatResult(
  result: Parameters<typeof toMarkdown>[0],
  format: OutputFormat
): string {
  switch (format) {
    case "json":
      return toJSON(result);
    case "sarif":
      return toSARIF(result);
    default:
      return toMarkdown(result);
  }
}

function printSummary(result: ReturnType<typeof scan> extends Promise<infer R> ? R : never): void {
  const { score, summary, findings } = result as Awaited<ReturnType<typeof scan>>;
  console.error(
    `\nScore: ${score}/100 | Critical: ${summary.critical} | High: ${summary.high} | Medium: ${summary.medium} | Low: ${summary.low}`
  );
  if (findings.length === 0) {
    console.error("No issues found ✅");
  }
}

function printAuditSummary(results: AuditResult[]): void {
  const total = results.reduce((s, r) => s + r.scan.findings.length, 0);
  const critical = results.reduce((s, r) => s + r.scan.summary.critical, 0);
  const high = results.reduce((s, r) => s + r.scan.summary.high, 0);
  const avgScore = Math.round(
    results.reduce((s, r) => s + r.scan.score, 0) / results.length
  );
  console.error(
    `Servers: ${results.length} | Total findings: ${total} | Critical: ${critical} | High: ${high} | Avg score: ${avgScore}/100`
  );
}
