import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
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

  it("skips files under examples/ by default", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-inc-"));
    mkdirSync(join(dir, "examples"), { recursive: true });
    writeFileSync(join(dir, "examples", "server.ts"), VULN_SERVER);

    const { findings, filesScanned } = await analyzeTypeScript(dir);
    expect(filesScanned).toBe(0);
    expect(findings).toHaveLength(0);
  });

  it("scans example files when includeTests is set", async () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-inc-"));
    mkdirSync(join(dir, "examples"), { recursive: true });
    writeFileSync(join(dir, "examples", "server.ts"), VULN_SERVER);

    const { findings, filesScanned } = await analyzeTypeScript(dir, {
      includeTests: true,
    });
    expect(filesScanned).toBe(1);
    expect(findings.some((f) => f.rule === "mcp-command-injection")).toBe(true);
  });
});
