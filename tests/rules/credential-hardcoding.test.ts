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

  it("detects known-prefix credential bound to a non-credential variable name (L11)", () => {
    const sf = makeProject(`
      const ANTHROPIC = "sk-ant-api03-AbCdEf0123456789GhIjKl0123456789MnOpQr0123456789StUvWx0123456789YzAbCdEfGhIjKl";
      const X = "ghp_abcdEFGHijklMNOPqrstUVWXyz0123456789";
    `);
    const findings = detectHardcodedCredentials(sf);
    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings.every((f) => f.rule === "mcp-hardcoded-credential")).toBe(true);
  });

  it("does NOT double-report a credential already caught by the name pass", () => {
    const sf = makeProject(`
      const apiKey = "sk-1234567890abcdefghijklmnopqrstuv";
    `);
    const findings = detectHardcodedCredentials(sf);
    expect(findings).toHaveLength(1);
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
