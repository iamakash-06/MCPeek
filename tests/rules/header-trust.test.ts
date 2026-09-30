import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectUntrustedContextAuthz } from "../../src/analyzers/rules/untrusted-context.js";

const scan = (code: string) =>
  detectUntrustedContextAuthz(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", code));

describe("header-trust", () => {
  it("flags Mcp-Name used in a routing decision", () => {
    const f = scan(`function route(req) { if (req.headers["mcp-name"] === "admin_tool") return adminHandler(req); }`);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: "mcp-header-trust", severity: "medium" });
  });

  it("flags Mcp-Method read through header() and get()", () => {
    expect(scan(`app.post("/mcp", (c) => { if (c.req.header("Mcp-Method") === "tools/call") return allow(c); });`)).toHaveLength(1);
    expect(scan(`function f(req) { switch (req.headers.get("Mcp-Method")) { case "tools/call": return 1; } }`)).toHaveLength(1);
  });

  it("does not require an MCP SDK import", () => {
    expect(scan(`const r = (req) => req.headers["mcp-method"] === "ping" ? 1 : 2;`)).toHaveLength(1);
  });

  it("accepts a handler that cross-checks the body", () => {
    const f = scan(`function route(req, body) {
      if (req.headers["mcp-name"] !== body.params.name) throw new Error("mismatch");
      if (req.headers["mcp-name"] === "admin_tool") return 1;
    }`);
    expect(f).toEqual([]);
  });

  it("ignores header reads that feed no decision", () => {
    expect(scan(`function log(req) { logger.info({ name: req.headers["mcp-name"] }); }`)).toEqual([]);
  });

  it("ignores response headers", () => {
    expect(scan(`function f(res) { if (res.getHeader("Mcp-Method") === "x") return 1; }`)).toEqual([]);
  });

  it("keeps the existing identity-header finding separate", () => {
    const f = scan(`import "@modelcontextprotocol/server";\nfunction f(req) { if (req.headers["x-user-role"] === "admin") return 1; }`);
    expect(f.map((x) => x.rule)).toEqual(["mcp-meta-authz"]);
  });
});
