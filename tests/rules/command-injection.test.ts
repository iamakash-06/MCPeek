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
    expect(findings[0].taintChain).toBeDefined();
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("execSync()");
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
    expect(findings[0].taintChain).toBeDefined();
    expect(findings[0].taintChain![0]).toContain("handler param");
  });

  it("tracks taint through variable aliases (multi-hop)", () => {
    const sf = makeProject(`
      server.tool("run", { scriptName: z.string() }, async ({ scriptName }) => {
        const cmd = scriptName;
        const full = \`./scripts/\${cmd}.sh\`;
        execSync(full);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].taintChain).toBeDefined();
    expect(findings[0].taintChain!.length).toBeGreaterThanOrEqual(3);
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("execSync()");
  });

  it("tracks taint through object destructuring (setRequestHandler pattern)", () => {
    const sf = makeProject(`
      server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { arguments: args } = request.params;
        const { command } = args;
        execSync(command);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].taintChain).toBeDefined();
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("execSync()");
  });

  it("does NOT see a custom registration wrapper by default (L7)", () => {
    const sf = makeProject(`
      function registerMyTool(name, handler) { /* ... */ }
      registerMyTool("run", async ({ cmd }) => {
        execSync(cmd);
        return { content: [] };
      });
    `);
    expect(detectCommandInjection(sf)).toHaveLength(0);
  });

  it("detects a custom registration wrapper when configured (L7)", () => {
    const sf = makeProject(`
      function registerMyTool(name, handler) { /* ... */ }
      registerMyTool("run", async ({ cmd }) => {
        execSync(cmd);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf, {
      extraRegistrations: ["registerMyTool"],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-command-injection");
    expect(findings[0].taintChain![0]).toContain("handler param");
  });

  it("matches a dotted custom registration name by its last segment", () => {
    const sf = makeProject(`
      tools.registerMyTool("run", async ({ cmd }) => {
        execSync(cmd);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf, {
      extraRegistrations: ["registerMyTool"],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT taint the context parameter by default (L6)", () => {
    const sf = makeProject(`
      server.tool("ctx", { x: z.string() }, async (input, context) => {
        execSync(context.userCmd);
        return { content: [] };
      });
    `);
    expect(detectCommandInjection(sf)).toHaveLength(0);
  });

  it("taints the context parameter when taintContextParam is set (L6)", () => {
    const sf = makeProject(`
      server.tool("ctx", { x: z.string() }, async (input, context) => {
        execSync(context.userCmd);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf, { taintContextParam: true });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-command-injection");
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

  it("detects taint flowing through an object field assignment (L5)", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      server.tool("run", { command: z.string() }, async ({ command }) => {
        const opts: any = {};
        opts.cmd = command;
        execSync(opts.cmd);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-command-injection");
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("execSync()");
  });

  it("detects taint flowing through a nested property assignment in a template", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      server.tool("run", { command: z.string() }, async ({ command }) => {
        const opts: any = {};
        opts.cmd = command;
        execSync(\`git \${opts.cmd}\`);
        return { content: [] };
      });
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
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
