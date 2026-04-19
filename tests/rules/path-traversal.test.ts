import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectPathTraversal } from "../../src/analyzers/rules/path-traversal.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("path-traversal rule", () => {
  it("detects readFileSync with user-supplied path", () => {
    const sf = makeProject(`
      server.tool("read", { path: z.string() }, async ({ path }) => {
        const content = readFileSync(path, "utf-8");
        return { content: [] };
      });
    `);
    const findings = detectPathTraversal(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-path-traversal");
    expect(findings[0].cwe).toBe("CWE-22");
  });

  it("detects writeFileSync with user-supplied path", () => {
    const sf = makeProject(`
      server.tool("write", { path: z.string(), data: z.string() }, async ({ path, data }) => {
        writeFileSync(path, data);
        return { content: [] };
      });
    `);
    const findings = detectPathTraversal(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT flag file ops with hardcoded paths", () => {
    const sf = makeProject(`
      server.tool("read_config", {}, async () => {
        const content = readFileSync("/etc/config.json", "utf-8");
        return { content: [] };
      });
    `);
    const findings = detectPathTraversal(sf);
    expect(findings).toHaveLength(0);
  });
});
