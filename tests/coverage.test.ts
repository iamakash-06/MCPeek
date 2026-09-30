import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { analyzeTypeScript } from "../src/analyzers/ts-analyzer.js";

const SERVER = `
  import { execSync } from "child_process";
  server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
    execSync(cmd);
    return { content: [] };
  });
`;

describe("scan coverage", () => {
  let dir: string;
  const write = (rel: string, code: string) => {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), code);
  };
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("reports a fully analyzed TypeScript server as assessed", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("src/server.ts", SERVER);
    const { coverage, warnings } = await analyzeTypeScript(dir);
    expect(coverage).toMatchObject({ assessed: true, filesAnalyzed: 1, handlers: 1, unsupported: {} });
    expect(warnings).toHaveLength(0);
  });

  it("marks a Python-only repo as not assessed", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("server.py", "print('hi')");
    write("tools/db.py", "print('db')");
    const { coverage, warnings } = await analyzeTypeScript(dir);
    expect(coverage.assessed).toBe(false);
    expect(coverage.unsupported).toEqual({ Python: 2 });
    expect(warnings[0]).toMatch(/Python: 2/);
  });

  it("warns when non-TS sources outnumber analyzed files", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("src/server.ts", SERVER);
    write("a.go", "package a");
    write("b.go", "package b");
    const { coverage, warnings } = await analyzeTypeScript(dir);
    expect(coverage.assessed).toBe(true);
    expect(warnings.some((w) => w.includes("Go: 2"))).toBe(true);
  });

  it("does not warn when TypeScript dominates", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("src/server.ts", SERVER);
    write("src/other.ts", "export const x = 1;");
    write("scripts/tool.py", "print(1)");
    const { warnings } = await analyzeTypeScript(dir);
    expect(warnings).toHaveLength(0);
  });

  it("skips vendored and generated files and counts them", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("src/server.ts", SERVER);
    write("extensions/2026-07-28/schema/spec.types.ts", SERVER);
    write("vendor/lib/server.ts", SERVER);
    const { coverage, findings } = await analyzeTypeScript(dir);
    expect(coverage.skipped.vendored).toBe(2);
    expect(coverage.filesAnalyzed).toBe(1);
    expect(findings.filter((f) => f.rule === "mcp-command-injection")).toHaveLength(1);
  });

  it("counts skipped test files and still analyzes examples", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("src/server.ts", SERVER);
    write("examples/demo.ts", SERVER);
    write("test/a.test.ts", SERVER);
    const { coverage } = await analyzeTypeScript(dir);
    expect(coverage.skipped.tests).toBe(1);
    expect(coverage.filesAnalyzed).toBe(2);
  });

  it("marks an SDK import with no detected handlers as not assessed", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-cov-"));
    write("src/server.ts", `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nregisterAll(new McpServer({}));`);
    const { coverage } = await analyzeTypeScript(dir);
    expect(coverage.assessed).toBe(false);
  });
});
