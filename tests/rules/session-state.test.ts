import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectSessionKeyedState } from "../../src/analyzers/rules/session-state.js";

const scan = (code: string) => detectSessionKeyedState(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", code));

describe("session-keyed-state", () => {
  it("flags a transport record indexed by the session header", () => {
    const f = scan(`
      const transports: Record<string, Transport> = {};
      app.post("/mcp", async (req, res) => {
        const sessionId = req.headers["mcp-session-id"] as string;
        const t = transports[sessionId];
      });`);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: "mcp-session-keyed-state", severity: "medium", line: 5 });
  });

  it("flags a Map with get/set by session id", () => {
    const f = scan(`
      const sessions = new Map<string, Transport>();
      function attach(sessionId: string, t: Transport) { sessions.set(sessionId, t); }`);
    expect(f).toHaveLength(1);
  });

  it("flags a session id generator", () => {
    const f = scan(`new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });`);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("low");
  });

  it("flags a store declared inside a function", () => {
    const f = scan(`function start() { const transports: TransportMap = {}; transports[sessionId] = t; }`);
    expect(f).toHaveLength(1);
  });

  it("accepts a generator that reuses a precomputed id", () => {
    expect(scan(`new StreamableHTTPServerTransport({ sessionIdGenerator: () => sealedSid });`)).toEqual([]);
  });

  it("accepts the stateless transport option", () => {
    expect(scan(`new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });`)).toEqual([]);
  });

  it("ignores a session-named map not keyed by a session id", () => {
    expect(scan(`const sessions = new Map();\nsessions.set(userId, 1);`)).toEqual([]);
  });

  it("ignores maps that are not session stores", () => {
    expect(scan(`const cache = new Map();\ncache.set(sessionId, 1);`)).toEqual([]);
  });

  it("ignores comments and strings", () => {
    expect(scan(`// const transports = {}; transports[sessionId]\nconst doc = "mcp-session-id";`)).toEqual([]);
  });
});
