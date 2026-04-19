import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectCommandInjection } from "../../src/analyzers/rules/command-injection.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("command-injection rule", () => {
  it("detects execSync called with tool handler param", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      server.tool("run", { command: z.string() }, async ({ command }) => {
        const result = execSync(command);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-command-injection");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].cwe).toBe("CWE-78");
  });

  it("detects spawn called with tool handler param", () => {
    const sf = makeProject(`
      import { spawn } from "child_process";
      server.tool("exec", { cmd: z.string() }, async ({ cmd }) => {
        spawn(cmd, []);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].cwe).toBe("CWE-78");
  });

  it("does NOT flag execSync with a hardcoded command", () => {
    const sf = makeProject(`
      server.tool("list", {}, async () => {
        const result = execSync("ls -la");
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag non-MCP code", () => {
    const sf = makeProject(`
      function runCommand(cmd: string) {
        return execSync(cmd);
      }
    `);
    const findings = detectCommandInjection(sf);
    expect(findings).toHaveLength(0);
  });
});
