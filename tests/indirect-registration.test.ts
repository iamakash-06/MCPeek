import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { findMCPToolHandlers } from "../src/analyzers/mcp-handler.js";
import { detectCommandInjection } from "../src/analyzers/rules/command-injection.js";
import { makeMultiFileProject, getFile } from "./helpers/multi-file-project.js";

const sf = (code: string) => new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", code);
const names = (code: string) => findMCPToolHandlers(sf(code)).map((h) => h.paramNames);

describe("handler factories", () => {
  it("follows a factory call passed directly", () => {
    expect(
      names(`
        function createHandler(cfg) { return async ({ v }) => { run(v); }; }
        server.registerTool("t", { inputSchema: { v: z.string() } }, createHandler(cfg));
      `)
    ).toEqual([["v"]]);
  });

  it("follows a factory result stored in a variable, through casts", () => {
    expect(
      names(`
        const createHandler = (kind) => { return (async (input) => run(input)) as Callback; };
        const h = createHandler("GET");
        server.registerTool("t", { inputSchema: { v: z.string() } }, h);
      `)
    ).toEqual([["input"]]);
  });

  it("follows an arrow-returning-arrow factory", () => {
    expect(
      names(`
        const make = (x) => async (args) => run(args);
        server.registerTool("t", { inputSchema: { a: z.string() } }, make(1));
      `)
    ).toEqual([["args"]]);
  });

  it("gives up on unresolvable or recursive factories", () => {
    expect(names(`server.registerTool("t", { inputSchema: {} }, unknownFactory());`)).toEqual([]);
    expect(names(`function f() { return f(); }\nserver.registerTool("t", { inputSchema: {} }, f());`)).toEqual([]);
  });

  it("resolves handlers imported from another file", () => {
    const project = makeMultiFileProject([
      { name: "handlers.ts", code: `import { exec } from "child_process";\nexport const make = () => async ({ cmd }) => { exec(cmd); };` },
      { name: "server.ts", code: `import { make } from "./handlers";\nserver.registerTool("t", { inputSchema: { cmd: z.string() } }, make());` },
    ]);
    const findings = detectCommandInjection(getFile(project, "server.ts"));
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toContain("handlers.ts");
  });
});

describe("tool definition objects", () => {
  it("finds handler, execute and cb members next to a schema", () => {
    expect(
      names(`
        defineTool({ name: "a", inputSchema: { q: z.string() }, async handler({ q }, ctx) {} });
        const b = { title: "b", inputSchema: schema, execute: async (input, opts) => {} };
        const c = { name: "c", description: "d", parameters: { p: z.string() }, cb: async (args, extra) => {} };
      `)
    ).toEqual([["q"], ["input"], ["args"]]);
  });

  it("treats cb without parameters as extra-only", () => {
    expect(names(`const c = { name: "c", description: "d", cb: async (extra) => {} };`)).toEqual([[]]);
  });

  it("ignores route-like objects and handlers without a schema", () => {
    expect(names(`const r = { path: "/x", handler: async (req) => {} };`)).toEqual([]);
    expect(names(`const r = { name: "x", description: "y", handler: async (req) => {} };`)).toEqual([]);
  });

  it("does not report a handler twice when it is also registered", () => {
    expect(
      names(`
        const def = { inputSchema: { v: z.string() }, handler: async ({ v }) => {} };
        server.registerTool("t", { inputSchema: def.inputSchema }, def.handler);
      `)
    ).toEqual([["v"]]);
  });

  it("feeds taint rules", () => {
    const f = detectCommandInjection(
      sf(`
        import { exec } from "child_process";
        export const tool = defineTool({ name: "x", inputSchema: { cmd: z.string() }, handler: async ({ cmd }) => { exec(cmd); } });
      `)
    );
    expect(f).toHaveLength(1);
  });
});
