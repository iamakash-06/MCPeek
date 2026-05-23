import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectWeakSchemaBounds } from "../../src/analyzers/rules/weak-schema-bounds.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("weak-schema-bounds rule", () => {
  it("flags z.string() with no bounds", () => {
    const sf = makeProject(`
      server.tool("search", { query: z.string() }, async ({ query }) => {
        return { content: [] };
      });
    `);
    const findings = detectWeakSchemaBounds(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("mcp-weak-schema-bounds");
    expect(findings[0].cwe).toBe("CWE-20");
    expect(findings[0].severity).toBe("medium");
    expect(findings[0].message).toContain("query");
  });

  it("flags z.number() with no bounds", () => {
    const sf = makeProject(`
      server.tool("count", { n: z.number() }, async ({ n }) => ({ content: [] }));
    `);
    const findings = detectWeakSchemaBounds(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain("n");
  });

  it("flags z.array() with no max", () => {
    const sf = makeProject(`
      server.tool("batch", { items: z.array(z.string().max(10)) }, async () => ({ content: [] }));
    `);
    const findings = detectWeakSchemaBounds(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain("items");
  });

  it("does NOT flag z.string().min().max()", () => {
    const sf = makeProject(`
      server.tool("safe", { name: z.string().min(1).max(100) }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag z.number() with .min().max()", () => {
    const sf = makeProject(`
      server.tool("ok", { n: z.number().min(0).max(1000) }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag z.number().int().positive()", () => {
    const sf = makeProject(`
      server.tool("ok", { n: z.number().int().positive() }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag z.string().email()", () => {
    const sf = makeProject(`
      server.tool("email", { addr: z.string().email() }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag z.string().regex(...)", () => {
    const sf = makeProject(`
      server.tool("p", { id: z.string().regex(/^[a-z0-9]+$/) }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag z.boolean() or z.enum() (not size-bounded types)", () => {
    const sf = makeProject(`
      server.tool("flag", { on: z.boolean(), level: z.enum(["a", "b"]) }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag z.any() or z.unknown() (other rule covers these)", () => {
    const sf = makeProject(`
      server.tool("loose", { x: z.any(), y: z.unknown() }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("does NOT flag tool registered without a schema (handler-only form)", () => {
    const sf = makeProject(`
      server.tool("nope", async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(0);
  });

  it("unwraps z.object({...}) wrapper", () => {
    const sf = makeProject(`
      server.tool("wrapped", z.object({ query: z.string() }), async () => ({ content: [] }));
    `);
    const findings = detectWeakSchemaBounds(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain("query");
  });

  it("caps at 2 findings per file to bound score impact", () => {
    const sf = makeProject(`
      server.tool("a", { q: z.string() }, async () => ({ content: [] }));
      server.tool("b", { q: z.string() }, async () => ({ content: [] }));
      server.tool("c", { q: z.string() }, async () => ({ content: [] }));
      server.tool("d", { q: z.string() }, async () => ({ content: [] }));
    `);
    expect(detectWeakSchemaBounds(sf)).toHaveLength(2);
  });

  it("lists multiple weak fields in one finding", () => {
    const sf = makeProject(`
      server.tool("multi", { a: z.string(), b: z.number() }, async () => ({ content: [] }));
    `);
    const findings = detectWeakSchemaBounds(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].message).toContain("a");
    expect(findings[0].message).toContain("b");
  });
});
