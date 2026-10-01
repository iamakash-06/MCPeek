import { describe, it, expect, beforeAll } from "vitest";
import { join } from "path";
import { scan } from "../src/scanner.js";
import type { ScanResult } from "../src/types.js";

const root = join(__dirname, "..", "showcase", "mcp-dev-summit-toronto");

// Every rule MCPeek ships. If a rule is added, add it here and to the vulnerable server.
const ALL_RULES = [
  "mcp-command-injection",
  "mcp-code-injection",
  "mcp-sql-injection",
  "mcp-path-traversal",
  "mcp-ssrf",
  "mcp-tool-poisoning",
  "mcp-missing-input-validation",
  "mcp-hardcoded-credential",
  "mcp-weak-input-validation",
  "mcp-weak-schema-bounds",
  "mcp-requeststate-unbound",
  "mcp-requeststate-weak-key",
  "mcp-requeststate-secret",
  "mcp-requeststate-authz-gap",
  "mcp-meta-authz",
  "mcp-header-trust",
  "mcp-session-keyed-state",
  "mcp-header-sensitive",
  "mcp-apps-html-xss",
  "mcp-apps-wildcard-csp",
  "mcp-signed-token-secret",
  "mcp-migration-push-request",
  "mcp-migration-removed-method",
  "mcp-migration-legacy-sdk",
  "mcp-migration-unbounded-sdk-range",
];

describe("MCP Dev Summit Toronto showcase", () => {
  let vulnerable: ScanResult;
  let clean: ScanResult;

  beforeAll(async () => {
    vulnerable = await scan(join(root, "vulnerable-v1"));
    clean = await scan(join(root, "clean-v2"));
  });

  it("vulnerable-v1 triggers every rule", () => {
    const fired = new Set(vulnerable.findings.map((f) => f.rule));
    expect(ALL_RULES.filter((r) => !fired.has(r))).toEqual([]);
  });

  it("vulnerable-v1 fails the security score and the migration score", () => {
    expect(vulnerable.score).toBeLessThan(20);
    expect(vulnerable.summary.critical).toBeGreaterThan(0);
    expect(vulnerable.migration.score).toBeLessThan(100);
  });

  it("vulnerable-v1 is not skipped as example or test code", () => {
    expect(vulnerable.findings.every((f) => !f.context)).toBe(true);
    expect(vulnerable.coverage.assessed).toBe(true);
  });

  it("vulnerable-v1 traces taint across files", () => {
    const sql = vulnerable.findings.find((f) => f.rule === "mcp-sql-injection" && f.file.endsWith("db.ts"));
    expect(sql?.taintChain?.length).toBeGreaterThan(1);
  });

  it("clean-v2 has no findings and a perfect score on both axes", () => {
    expect(clean.findings).toEqual([]);
    expect(clean.score).toBe(100);
    expect(clean.migration.score).toBe(100);
    expect(clean.coverage.assessed).toBe(true);
    expect(clean.coverage.handlers).toBeGreaterThan(10);
  });
});
