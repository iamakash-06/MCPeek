import { describe, it, expect } from "vitest";
import { SyntaxKind } from "ts-morph";
import { resolveCallee } from "../src/analyzers/cross-file.js";
import { makeMultiFileProject } from "./helpers/multi-file-project.js";

function firstCallTo(sf: any, exprText: string) {
  return sf
    .getDescendantsOfKind(SyntaxKind.CallExpression)
    .find((c: any) => c.getExpression().getText() === exprText);
}

describe("resolveCallee", () => {
  it("resolves a local function declaration", () => {
    const project = makeMultiFileProject([
      {
        name: "a.ts",
        code: `
          function helper(cmd: string) { return cmd; }
          helper("ls");
        `,
      },
    ]);
    const sf = project.getSourceFileOrThrow("a.ts");
    const call = firstCallTo(sf, "helper");
    const r = resolveCallee(call, sf);
    expect(r).toBeDefined();
    expect(r!.paramNames).toEqual(["cmd"]);
    expect(r!.fnName).toBe("helper");
  });

  it("resolves a local arrow function variable", () => {
    const project = makeMultiFileProject([
      {
        name: "a.ts",
        code: `
          const helper = (cmd: string) => cmd;
          helper("ls");
        `,
      },
    ]);
    const sf = project.getSourceFileOrThrow("a.ts");
    const r = resolveCallee(firstCallTo(sf, "helper"), sf);
    expect(r!.paramNames).toEqual(["cmd"]);
  });

  it("resolves an imported function across files", () => {
    const project = makeMultiFileProject([
      {
        name: "helper.ts",
        code: `export function runShell(cmd: string) { return cmd; }`,
      },
      {
        name: "server.ts",
        code: `
          import { runShell } from "./helper.js";
          runShell("ls");
        `,
      },
    ]);
    const server = project.getSourceFileOrThrow("server.ts");
    const r = resolveCallee(firstCallTo(server, "runShell"), server);
    expect(r).toBeDefined();
    expect(r!.paramNames).toEqual(["cmd"]);
    expect(r!.file).toContain("helper.ts");
  });

  it("resolves an imported class method across files", () => {
    const project = makeMultiFileProject([
      {
        name: "lib.ts",
        code: `
          export class Worker {
            run(cmd: string) { return cmd; }
          }
        `,
      },
      {
        name: "server.ts",
        code: `
          import { Worker } from "./lib.js";
          const w = new Worker();
          Worker.run("ls");
        `,
      },
    ]);
    const server = project.getSourceFileOrThrow("server.ts");
    const r = resolveCallee(firstCallTo(server, "Worker.run"), server);
    expect(r).toBeDefined();
    expect(r!.paramNames).toEqual(["cmd"]);
    expect(r!.fnName).toBe("Worker.run");
  });

  it("returns undefined for library receivers like fs.readFile", () => {
    const project = makeMultiFileProject([
      {
        name: "a.ts",
        code: `
          import * as fs from "fs";
          fs.readFile("x");
        `,
      },
    ]);
    const sf = project.getSourceFileOrThrow("a.ts");
    const r = resolveCallee(firstCallTo(sf, "fs.readFile"), sf);
    expect(r).toBeUndefined();
  });

  it("returns undefined for a function with too many parameters", () => {
    const project = makeMultiFileProject([
      {
        name: "a.ts",
        code: `
          function big(a, b, c, d, e, f, g, h, i) { return a; }
          big(1, 2, 3, 4, 5, 6, 7, 8, 9);
        `,
      },
    ]);
    const sf = project.getSourceFileOrThrow("a.ts");
    const r = resolveCallee(firstCallTo(sf, "big"), sf);
    expect(r).toBeUndefined();
  });
});
