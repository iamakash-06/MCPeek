import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectCommandInjection } from "../../src/analyzers/rules/command-injection.js";
import { makeMultiFileProject } from "../helpers/multi-file-project.js";

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

  it("does NOT flag input passed through shellEscape before reaching the sink (L3)", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      import shellEscape from "shell-escape";
      server.tool("run", { command: z.string() }, async ({ command }) => {
        const safe = shellEscape([command]);
        execSync(\`git \${safe}\`);
        return { content: [] };
      });
    `);
    expect(detectCommandInjection(sf)).toHaveLength(0);
  });

  it("does NOT flag input passed through assignment-form shellQuote", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      import { quote as shellQuote } from "shell-quote";
      server.tool("run", { command: z.string() }, async ({ command }) => {
        let safe;
        safe = shellQuote([command]);
        execSync(safe);
        return { content: [] };
      });
    `);
    expect(detectCommandInjection(sf)).toHaveLength(0);
  });

  it("follows taint into an imported helper function one hop away (L1)", () => {
    const project = makeMultiFileProject([
      {
        name: "helper.ts",
        code: `
          import { execSync } from "child_process";
          export function runShell(cmd: string) { return execSync(cmd); }
        `,
      },
      {
        name: "server.ts",
        code: `
          import { runShell } from "./helper.js";
          server.tool("run", { command: z.string() }, async ({ command }) => {
            runShell(command);
            return { content: [] };
          });
        `,
      },
    ]);
    const findings = detectCommandInjection(project.getSourceFileOrThrow("server.ts"));
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const cross = findings.find((f) => f.file.endsWith("helper.ts"));
    expect(cross).toBeDefined();
    expect(cross!.confidence).toBe("medium");
    expect(cross!.taintChain![0]).toContain("handler param");
    expect(cross!.taintChain![cross!.taintChain!.length - 1]).toContain("execSync()");
  });

  it("follows taint into an imported class method one hop away (markdownify-mcp shape)", () => {
    const project = makeMultiFileProject([
      {
        name: "Markdownify.ts",
        code: `
          import { execSync } from "child_process";
          export class Markdownify {
            static get(filePath: string) { return execSync(\`pandoc \${filePath}\`); }
          }
        `,
      },
      {
        name: "server.ts",
        code: `
          import { Markdownify } from "./Markdownify.js";
          server.tool("convert", { filePath: z.string() }, async ({ filePath }) => {
            Markdownify.get(filePath);
            return { content: [] };
          });
        `,
      },
    ]);
    const findings = detectCommandInjection(project.getSourceFileOrThrow("server.ts"));
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const cross = findings.find((f) => f.file.endsWith("Markdownify.ts"));
    expect(cross).toBeDefined();
  });

  it("matches a handler passed by reference to a local const (L7)", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      const runHandler = async ({ command }) => {
        execSync(command);
        return { content: [] };
      };
      server.tool("run", { command: z.string() }, runHandler);
    `);
    const findings = detectCommandInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("tracks taint through bracketed element-access write and read", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      server.tool("run", { command: z.string() }, async ({ command }) => {
        const opts: any = {};
        opts["cmd"] = command;
        execSync(opts["cmd"]);
        return { content: [] };
      });
    `);
    expect(detectCommandInjection(sf).length).toBeGreaterThanOrEqual(1);
  });

  it("matches a handler imported from another file (L7)", () => {
    const project = makeMultiFileProject([
      {
        name: "handlers.ts",
        code: `
          import { execSync } from "child_process";
          export const runHandler = async ({ command }) => {
            execSync(command);
            return { content: [] };
          };
        `,
      },
      {
        name: "server.ts",
        code: `
          import { runHandler } from "./handlers.js";
          server.tool("run", { command: z.string() }, runHandler);
        `,
      },
    ]);
    const findings = detectCommandInjection(project.getSourceFileOrThrow("server.ts"));
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-command-injection");
  });

  it("matches a handler passed as a function declaration reference", () => {
    const sf = makeProject(`
      import { execSync } from "child_process";
      async function runHandler({ command }) {
        execSync(command);
        return { content: [] };
      }
      server.tool("run", { command: z.string() }, runHandler);
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
