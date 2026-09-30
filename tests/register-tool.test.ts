import { describe, it, expect } from "vitest";
import { join } from "path";
import { Project } from "ts-morph";
import { analyzeTypeScript } from "../src/analyzers/ts-analyzer.js";
import { findMCPToolHandlers } from "../src/analyzers/mcp-handler.js";
import { detectCommandInjection } from "../src/analyzers/rules/command-injection.js";
import { detectSSRF } from "../src/analyzers/rules/ssrf.js";
import { detectPathTraversal } from "../src/analyzers/rules/path-traversal.js";
import { detectSqlInjection } from "../src/analyzers/rules/sql-injection.js";
import { detectCodeInjection } from "../src/analyzers/rules/code-injection.js";
import { detectMissingInputValidation } from "../src/analyzers/rules/input-validation.js";
import { detectWeakSchemaBounds } from "../src/analyzers/rules/weak-schema-bounds.js";

function sf(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  return project.createSourceFile("test.ts", code);
}

const reg = (schema: string, body: string, params = "{ v }") => `
  server.registerTool("t", { description: "d", ${schema} }, async (${params}) => {
    ${body}
    return { content: [] };
  });
`;

describe("registerTool handlers", () => {
  it("enters the handler and taints destructured input", () => {
    const handlers = findMCPToolHandlers(
      sf(reg("inputSchema: { v: z.string() }", "exec(v);"))
    );
    expect(handlers).toHaveLength(1);
    expect(handlers[0].paramNames).toEqual(["v"]);
  });

  it("does not taint the extra param", () => {
    const [h] = findMCPToolHandlers(
      sf(reg("inputSchema: { v: z.string() }", "exec(v);", "{ v }, extra"))
    );
    expect(h.paramNames).toEqual(["v"]);
  });

  it("does not taint extra when there is no inputSchema", () => {
    const [h] = findMCPToolHandlers(sf(reg("", "exec(extra);", "extra")));
    expect(h.paramNames).toEqual([]);
  });

  it("works on aliased receivers", () => {
    expect(
      detectCommandInjection(
        sf(`
        import { exec } from "child_process";
        this.mcp.registerTool("t", { inputSchema: { v: z.string() } }, async ({ v }) => { exec(v); });
      `)
      ).length
    ).toBe(1);
  });

  it("taint rules fire", () => {
    const run = (fn: (f: any) => any[], body: string, imports = "") =>
      fn(sf(`${imports}\n${reg("inputSchema: { v: z.string() }", body)}`));
    expect(run(detectCommandInjection, "execSync(v);", 'import { execSync } from "child_process";').length).toBe(1);
    expect(run(detectSSRF, "await fetch(v);").length).toBe(1);
    expect(run(detectPathTraversal, "readFileSync(v);", 'import { readFileSync } from "fs";').length).toBe(1);
    expect(run(detectSqlInjection, "await db.query(v);").length).toBe(1);
    expect(run(detectCodeInjection, "eval(v);").length).toBe(1);
  });

  it("does not flag hardcoded sinks", () => {
    expect(
      detectSSRF(sf(reg("inputSchema: { v: z.string() }", 'await fetch("https://x.test");'))).length
    ).toBe(0);
  });
});

describe("registerTool schema rules", () => {
  it("flags unbounded fields in inputSchema", () => {
    const f = detectWeakSchemaBounds(sf(reg("inputSchema: { v: z.string() }", "")));
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain("v");
  });

  it("resolves inputSchema through z.object and identifiers", () => {
    const code = `
      const shape = { v: z.string() };
      server.registerTool("a", { inputSchema: z.object(shape) }, async ({ v }) => ({}));
      server.registerTool("b", { inputSchema: shape }, async ({ v }) => ({}));
    `;
    expect(detectWeakSchemaBounds(sf(code))).toHaveLength(2);
  });

  it("does not flag bounded fields or tools without inputSchema", () => {
    expect(
      detectWeakSchemaBounds(sf(reg("inputSchema: { v: z.string().max(10) }", "")))
    ).toHaveLength(0);
    expect(detectWeakSchemaBounds(sf(reg("", "", "extra")))).toHaveLength(0);
  });

  it("flags z.any() in inputSchema", () => {
    const f = detectMissingInputValidation(sf(reg("inputSchema: { v: z.any() }", "")));
    expect(f.map((x) => x.rule)).toContain("mcp-weak-input-validation");
  });

  it("does not report missing schema for tools with no inputSchema", () => {
    expect(detectMissingInputValidation(sf(reg("", "", "extra")))).toHaveLength(0);
  });
});

describe("v1 / v2 parity", () => {
  const summarize = async (dir: string) => {
    const { findings } = await analyzeTypeScript(join(__dirname, "fixtures", dir), { includeTests: true });
    return findings.map((f) => `${f.rule}:${f.severity}`).sort();
  };

  it("reports the same rules and severities for both syntaxes", async () => {
    const v1 = await summarize("vulnerable-parity-v1");
    const v2 = await summarize("vulnerable-parity-v2");
    expect(v1).toContain("mcp-command-injection:critical");
    expect(v1).toContain("mcp-ssrf:high");
    expect(v2).toEqual(v1);
  });
});
