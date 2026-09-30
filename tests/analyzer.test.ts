import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { scan, hasCriticalOrHighFindings } from "../src/scanner.js";
import { analyzeTypeScript } from "../src/analyzers/ts-analyzer.js";

const VULN_SERVER = `
  import { execSync } from "child_process";
  server.tool("run", { cmd: z.string() }, async ({ cmd }) => {
    execSync(cmd);
    return { content: [] };
  });
`;

describe("analyzeTypeScript — --include-tests (L15)", () => {
  let dir: string;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("scans files under examples/ by default and tags their findings", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-inc-"));
    mkdirSync(join(dir, "examples"), { recursive: true });
    writeFileSync(join(dir, "examples", "server.ts"), VULN_SERVER);

    const { findings, filesScanned } = await analyzeTypeScript(dir);
    expect(filesScanned).toBe(1);
    const hit = findings.find((f) => f.rule === "mcp-command-injection");
    expect(hit?.context).toBe("example");
  });

  it("skips test files by default", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-inc-"));
    mkdirSync(join(dir, "test"), { recursive: true });
    writeFileSync(join(dir, "test", "server.ts"), VULN_SERVER);

    const { findings, filesScanned } = await analyzeTypeScript(dir);
    expect(filesScanned).toBe(0);
    expect(findings).toHaveLength(0);
  });

  it("scans and tags test files when includeTests is set", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-inc-"));
    mkdirSync(join(dir, "test"), { recursive: true });
    writeFileSync(join(dir, "test", "server.ts"), VULN_SERVER);

    const { findings, filesScanned } = await analyzeTypeScript(dir, {
      includeTests: true,
    });
    expect(filesScanned).toBe(1);
    expect(findings.find((f) => f.rule === "mcp-command-injection")?.context).toBe("test");
  });

  it("leaves example and test findings out of the score and CI gate", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-inc-"));
    mkdirSync(join(dir, "examples"), { recursive: true });
    writeFileSync(join(dir, "examples", "server.ts"), VULN_SERVER);

    const result = await scan(dir);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.score).toBe(100);
    expect(result.summary.critical).toBe(0);
    expect(hasCriticalOrHighFindings(result, "low")).toBe(false);
  });
});
