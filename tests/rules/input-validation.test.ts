import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectMissingInputValidation } from "../../src/analyzers/rules/input-validation.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("input-validation rule", () => {
  it("detects server.tool with no schema (2-arg form)", () => {
    const sf = makeProject(`
      server.tool("get_data", async (params) => {
        return { content: [] };
      });
    `);
    const findings = detectMissingInputValidation(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-missing-input-validation");
    expect(findings[0].cwe).toBe("CWE-20");
  });

  it("detects z.any() as weak validation", () => {
    const sf = makeProject(`
      server.tool("search", { query: z.any() }, async ({ query }) => {
        return { content: [] };
      });
    `);
    const findings = detectMissingInputValidation(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-weak-input-validation");
  });

  it("does NOT flag server.tool with proper Zod schema", () => {
    const sf = makeProject(`
      server.tool("safe", { name: z.string().min(1).max(100) }, async ({ name }) => {
        return { content: [] };
      });
    `);
    const findings = detectMissingInputValidation(sf);
    expect(findings).toHaveLength(0);
  });
});
