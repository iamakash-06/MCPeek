import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectCodeInjection } from "../../src/analyzers/rules/code-injection.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("code-injection rule", () => {
  it("detects eval called with tool handler param", () => {
    const sf = makeProject(`
      server.tool("run", { expr: z.string() }, async ({ expr }) => {
        const result = eval(expr);
        return { content: [] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-code-injection");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].cwe).toBe("CWE-94");
    expect(findings[0].taintChain).toBeDefined();
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("eval()");
  });

  it("detects new Function() built from a tool handler param", () => {
    const sf = makeProject(`
      server.tool("compile", { src: z.string() }, async ({ src }) => {
        const fn = new Function("ctx", src);
        return { content: [] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].cwe).toBe("CWE-94");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("new Function()");
  });

  it("detects vm.runInNewContext with tainted code", () => {
    const sf = makeProject(`
      import vm from "vm";
      server.tool("run", { code: z.string() }, async ({ code }) => {
        const result = vm.runInNewContext(code, {});
        return { content: [] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("runInNewContext()");
  });

  it("detects new vm.Script() with tainted source", () => {
    const sf = makeProject(`
      import vm from "vm";
      server.tool("compile", { src: z.string() }, async ({ src }) => {
        const script = new vm.Script(src);
        return { content: [] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("new Script()");
  });

  it("tracks taint through alias variables", () => {
    const sf = makeProject(`
      server.tool("run", { userExpr: z.string() }, async ({ userExpr }) => {
        const expr = userExpr;
        const wrapped = \`return (\${expr});\`;
        eval(wrapped);
        return { content: [] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].taintChain!.length).toBeGreaterThanOrEqual(3);
    expect(findings[0].taintChain![0]).toContain("handler param");
  });

  it("does NOT flag eval with a hardcoded string", () => {
    const sf = makeProject(`
      server.tool("greet", {}, async () => {
        const r = eval("1+1");
        return { content: [] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag eval outside MCP handlers", () => {
    const sf = makeProject(`
      function run(src: string) {
        return eval(src);
      }
    `);
    const findings = detectCodeInjection(sf);
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag new Function with only static arg names and no tainted body", () => {
    const sf = makeProject(`
      server.tool("run", { name: z.string() }, async ({ name }) => {
        const fn = new Function("a", "b", "return a + b;");
        return { content: [name] };
      });
    `);
    const findings = detectCodeInjection(sf);
    expect(findings).toHaveLength(0);
  });
});
