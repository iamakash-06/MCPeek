import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectPathTraversal } from "../../src/analyzers/rules/path-traversal.js";
import { makeMultiFileProject } from "../helpers/multi-file-project.js";

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
    expect(findings[0].taintChain).toBeDefined();
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("readFileSync()");
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

  it("detects taint flowing through an object field assignment (L5)", () => {
    const sf = makeProject(`
      server.tool("read", { path: z.string() }, async ({ path }) => {
        const opts: any = {};
        opts.target = path;
        const content = readFileSync(opts.target, "utf-8");
        return { content: [] };
      });
    `);
    const findings = detectPathTraversal(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-path-traversal");
    expect(findings[0].taintChain![0]).toContain("handler param");
    expect(findings[0].taintChain![findings[0].taintChain!.length - 1]).toContain("readFileSync()");
  });

  it("flags single-argument path.resolve wrapper as not safe (L4)", () => {
    const sf = makeProject(`
      import * as path from "path";
      server.tool("read", { p: z.string() }, async ({ p }) => {
        const content = readFileSync(path.resolve(p), "utf-8");
        return { content: [] };
      });
    `);
    const findings = detectPathTraversal(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0].rule).toBe("mcp-path-traversal");
  });

  it("flags path.resolve(BASE, p) without a containment check", () => {
    const sf = makeProject(`
      import * as path from "path";
      const BASE = "/srv/data";
      server.tool("read", { p: z.string() }, async ({ p }) => {
        const content = readFileSync(path.resolve(BASE, p), "utf-8");
        return { content: [] };
      });
    `);
    const findings = detectPathTraversal(sf);
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("does NOT flag path.resolve(BASE, p) gated by a startsWith containment check", () => {
    const sf = makeProject(`
      import * as path from "path";
      const BASE = "/srv/data";
      server.tool("read", { p: z.string() }, async ({ p }) => {
        const safe = path.resolve(BASE, p);
        if (!safe.startsWith(BASE)) throw new Error("escape");
        const content = readFileSync(safe, "utf-8");
        return { content: [] };
      });
    `);
    expect(detectPathTraversal(sf)).toHaveLength(0);
  });

  it("flags VDUO: containment check on derived var but sink reads original (L4)", () => {
    const sf = makeProject(`
      import * as path from "path";
      const BASE = "/srv/data";
      server.tool("read", { p: z.string() }, async ({ p }) => {
        const safe = path.resolve(BASE, p);
        if (!safe.startsWith(BASE)) throw new Error("escape");
        const content = readFileSync(p, "utf-8");
        return { content: [] };
      });
    `);
    expect(detectPathTraversal(sf).length).toBeGreaterThanOrEqual(1);
  });

  it("follows taint into an imported helper that calls readFileSync (L1)", () => {
    const project = makeMultiFileProject([
      {
        name: "helper.ts",
        code: `
          import { readFileSync } from "fs";
          export function readUserFile(p: string) { return readFileSync(p, "utf8"); }
        `,
      },
      {
        name: "server.ts",
        code: `
          import { readUserFile } from "./helper.js";
          server.tool("read", { path: z.string() }, async ({ path }) => {
            readUserFile(path);
            return { content: [] };
          });
        `,
      },
    ]);
    const findings = detectPathTraversal(project.getSourceFileOrThrow("server.ts"));
    const cross = findings.find((f) => f.file.endsWith("helper.ts"));
    expect(cross).toBeDefined();
    expect(cross!.confidence).toBe("medium");
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
