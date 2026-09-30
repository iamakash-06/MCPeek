import { describe, it, expect, afterEach } from "vitest";
import { Project } from "ts-morph";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { detectMigrationReadiness } from "../../src/analyzers/rules/migration.js";
import { scanManifests } from "../../src/analyzers/manifest-scanner.js";

const scan = (code: string) =>
  detectMigrationReadiness(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", `import "@modelcontextprotocol/sdk";\n${code}`));
const rules = (f: { rule: string }[]) => f.map((x) => x.rule);

describe("migration: push-style requests", () => {
  it("flags elicitInput, createMessage and listRoots on server-side receivers", () => {
    const f = scan(`
      await server.server.elicitInput({ message: "ok?" });
      await ctx.mcpReq.elicitInput({ message: "ok?" });
      await server.createMessage({ messages: [] });
      await server.listRoots();`);
    expect(rules(f)).toEqual(Array(4).fill("mcp-migration-push-request"));
  });

  it("flags the raw method strings", () => {
    expect(rules(scan(`server.request({ method: "elicitation/create", params: {} });`))).toEqual(["mcp-migration-push-request"]);
  });

  it("ignores createMessage on unrelated receivers", () => {
    expect(scan(`await slack.createMessage({ text: "hi" });`)).toEqual([]);
  });

  it("does not flag the v2 inputRequired.elicit helper", () => {
    expect(scan(`return inputRequired({ inputRequests: { c: inputRequired.elicit({ message: "ok?" }) } });`)).toEqual([]);
  });

  it("ignores files that do not use the MCP SDK", () => {
    const f = detectMigrationReadiness(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", `await server.listRoots();`));
    expect(f).toEqual([]);
  });
});

describe("migration: removed methods", () => {
  it("flags ping, roots-changed and set-level", () => {
    const f = scan(`
      await client.ping();
      await server.sendRootsListChanged();
      server.setRequestHandler(SetLevelRequestSchema, async () => ({}));
      server.notification({ method: "notifications/roots/list_changed" });`);
    expect(rules(f)).toEqual(Array(4).fill("mcp-migration-removed-method"));
  });

  it("does not flag ping on unrelated receivers or ordinary method strings", () => {
    expect(scan(`await host.ping();\nconst a = { method: "tools/call" };`)).toEqual([]);
  });
});

describe("migration: manifests", () => {
  let dir: string;
  afterEach(() => rmSync(dir, { recursive: true, force: true }));
  const manifest = (deps: Record<string, string>, rel = "package.json") => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-man-"));
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), JSON.stringify({ dependencies: deps }, null, 2));
    return scanManifests(dir);
  };

  it("notes the v1 sdk package", () => {
    const f = manifest({ "@modelcontextprotocol/sdk": "^1.24.3" });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: "mcp-migration-legacy-sdk", severity: "info", line: 3 });
  });

  it("flags unbounded ranges", () => {
    expect(rules(manifest({ "@modelcontextprotocol/server": "latest" }))).toEqual(["mcp-migration-unbounded-sdk-range"]);
    expect(rules(manifest({ "@modelcontextprotocol/server": ">=2.0.0" }))).toEqual(["mcp-migration-unbounded-sdk-range"]);
  });

  it("accepts pinned and caret ranges on the v2 package", () => {
    expect(manifest({ "@modelcontextprotocol/server": "2.0.0" })).toEqual([]);
    expect(manifest({ "@modelcontextprotocol/server": "^2.0.0" })).toEqual([]);
  });

  it("ignores unrelated packages and skips node_modules", () => {
    expect(manifest({ zod: "*" })).toEqual([]);
    expect(manifest({ "@modelcontextprotocol/server": "*" }, "node_modules/x/package.json")).toEqual([]);
  });

  it("ignores dependencies on packages defined in the same repo", () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-man-"));
    mkdirSync(join(dir, "src/memory"), { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ dependencies: { "@modelcontextprotocol/server-memory": "*" } }));
    writeFileSync(join(dir, "src/memory/package.json"), JSON.stringify({ name: "@modelcontextprotocol/server-memory" }));
    expect(scanManifests(dir)).toEqual([]);
  });

  it("ignores * ranges in a workspace root", () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-man-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ workspaces: ["src/*"], dependencies: { "@modelcontextprotocol/server-memory": "*" } }));
    expect(scanManifests(dir)).toEqual([]);
  });

  it("tags example manifests", () => {
    const f = manifest({ "@modelcontextprotocol/sdk": "1.0.0" }, "examples/demo/package.json");
    expect(f[0].context).toBe("example");
  });
});
