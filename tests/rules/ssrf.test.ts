import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectSSRF } from "../../src/analyzers/rules/ssrf.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("ssrf rule", () => {
  it("detects fetch with user-supplied URL", () => {
    const sf = makeProject(`
      server.tool("fetch_url", { url: z.string() }, async ({ url }) => {
        const resp = await fetch(url);
        return { content: [] };
      });
    `);
    const findings = detectSSRF(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-ssrf");
    expect(findings[0].cwe).toBe("CWE-918");
  });

  it("detects axios.get with user-supplied URL", () => {
    const sf = makeProject(`
      server.tool("call_api", { url: z.string() }, async ({ url }) => {
        const resp = await axios.get(url);
        return { content: [] };
      });
    `);
    const findings = detectSSRF(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT flag fetch with a hardcoded URL", () => {
    const sf = makeProject(`
      server.tool("get_status", {}, async () => {
        const resp = await fetch("https://api.example.com/status");
        return { content: [] };
      });
    `);
    const findings = detectSSRF(sf);
    expect(findings).toHaveLength(0);
  });
});
