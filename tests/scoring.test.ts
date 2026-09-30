import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { scan, hasCriticalOrHighFindings } from "../src/scanner.js";

const SESSION_SERVER = `
  const transports: Record<string, Transport> = {};
  server.tool("noop", { a: z.string().max(10) }, async ({ a }) => ({ content: [] }));
  export const get = (sessionId: string) => transports[sessionId];
`;

const CMD_SERVER = `
  import { execSync } from "child_process";
  server.tool("run", { cmd: z.string().max(10) }, async ({ cmd }) => {
    execSync(cmd);
    return { content: [] };
  });
`;

describe("scoring", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const scanCode = (code: string) => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-score-"));
    writeFileSync(join(dir, "server.ts"), code);
    return scan(dir);
  };

  it("scores migration findings separately from security", async () => {
    const r = await scanCode(SESSION_SERVER);
    expect(r.findings.some((f) => f.rule === "mcp-session-keyed-state")).toBe(true);
    expect(r.score).toBe(100);
    expect(r.summary.medium).toBe(0);
    expect(r.migration.score).toBe(96);
    expect(r.migration.summary.medium).toBe(1);
  });

  it("does not fail the CI gate on migration findings", async () => {
    const r = await scanCode(SESSION_SERVER);
    expect(hasCriticalOrHighFindings(r, "low")).toBe(false);
  });

  it("deducts a high-confidence critical finding in full and keeps it out of migration", async () => {
    const r = await scanCode(CMD_SERVER);
    const f = r.findings.find((x) => x.rule === "mcp-command-injection")!;
    expect(f.confidence).toBe("high");
    expect(r.score).toBe(75);
    expect(r.migration.score).toBe(100);
    expect(hasCriticalOrHighFindings(r, "high")).toBe(true);
  });

  it("weights medium-confidence findings at 80%", async () => {
    const r = await scanCode(`export function route(req: any) { if (req.headers["mcp-name"] === "admin") return 1; }`);
    const f = r.findings.find((x) => x.rule === "mcp-header-trust")!;
    expect(f).toMatchObject({ severity: "medium", confidence: "medium" });
    expect(r.score).toBe(96);
  });
});
