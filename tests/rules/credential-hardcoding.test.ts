import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectHardcodedCredentials } from "../../src/analyzers/rules/credential-hardcoding.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("credential-hardcoding rule", () => {
  it("detects hardcoded API key with known prefix", () => {
    const sf = makeProject(`
      const apiKey = "sk-1234567890abcdefghijklmnopqrstuv";
    `);
    const findings = detectHardcodedCredentials(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-hardcoded-credential");
    expect(findings[0].cwe).toBe("CWE-798");
  });

  it("detects hardcoded GitHub token", () => {
    const sf = makeProject(`
      const token = "ghp_abcdefghijklmnopqrstuvwxyz123456789";
    `);
    const findings = detectHardcodedCredentials(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT flag process.env usage", () => {
    const sf = makeProject(`
      const apiKey = process.env.OPENAI_API_KEY;
      const token = process.env.GITHUB_TOKEN ?? "";
    `);
    const findings = detectHardcodedCredentials(sf);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag short placeholder strings", () => {
    const sf = makeProject(`
      const apiKey = "YOUR_KEY_HERE";
      const secret = "change-me";
    `);
    const findings = detectHardcodedCredentials(sf);
    expect(findings).toHaveLength(0);
  });
});
