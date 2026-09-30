import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectRequestState } from "../../src/analyzers/rules/request-state.js";
import { detectSensitiveHeaderMapping } from "../../src/analyzers/rules/header-sensitive.js";
import { detectUntrustedContextAuthz } from "../../src/analyzers/rules/untrusted-context.js";
import { detectAppsHtmlXss } from "../../src/analyzers/rules/apps-xss.js";
import { findMCPToolHandlers } from "../../src/analyzers/mcp-handler.js";

const sf = (code: string) => new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", code);
const rules = (f: { rule: string }[]) => f.map((x) => x.rule);

describe("request-state", () => {
  it("flags a codec without bind", () => {
    const f = detectRequestState(sf(`const c = createRequestStateCodec({ key: process.env.K! });`));
    expect(rules(f)).toEqual(["mcp-requeststate-unbound"]);
  });

  it("accepts a bound codec with an env key", () => {
    const f = detectRequestState(sf(`const c = createRequestStateCodec({ key: process.env.K!, bind: (ctx) => ctx.mcpReq.method });`));
    expect(f).toEqual([]);
  });

  it("resolves options passed by reference", () => {
    const f = detectRequestState(sf(`const opts = { key: k };\nconst c = createRequestStateCodec(opts);`));
    expect(rules(f)).toEqual(["mcp-requeststate-unbound"]);
  });

  it("skips codecs whose options cannot be resolved", () => {
    expect(detectRequestState(sf(`const c = createRequestStateCodec(getOptions());`))).toEqual([]);
    expect(detectRequestState(sf(`const c = createRequestStateCodec({ ...base });`))).toEqual([]);
  });

  it("flags hardcoded keys, including env fallbacks", () => {
    for (const key of [`"0123456789abcdef0123456789abcdef"`, `process.env.K ?? "0123456789abcdef0123456789abcdef"`]) {
      const f = detectRequestState(sf(`createRequestStateCodec({ key: ${key}, bind: b });`));
      expect(f).toHaveLength(1);
      expect(f[0]).toMatchObject({ rule: "mcp-requeststate-weak-key", severity: "high" });
    }
  });

  it("flags per-process random keys as medium", () => {
    const f = detectRequestState(sf(`const KEY = randomBytes(32);\ncreateRequestStateCodec({ key: KEY, bind: b });`));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: "mcp-requeststate-weak-key", severity: "medium" });
  });

  it("flags secrets minted into state", () => {
    const code = `
      const codec = createRequestStateCodec({ key: k, bind: b });
      async function h(ctx, apiKey) {
        return codec.mint({ step: "a", apiKey }, ctx);
      }
      async function g(ctx) {
        return codec.mint({ step: "a", auth: process.env.SERVICE_URL }, ctx);
      }
      async function i(ctx, info) {
        return codec.mint({ creds: info.authInfo.token }, ctx);
      }
    `;
    expect(detectRequestState(sf(code)).map((x) => x.rule)).toEqual([
      "mcp-requeststate-secret",
      "mcp-requeststate-secret",
      "mcp-requeststate-secret",
    ]);
  });

  it("does not flag benign state or pagination tokens", () => {
    const code = `
      const codec = createRequestStateCodec({ key: k, bind: b });
      codec.mint({ step: "confirm", env, nextToken, maxTokens: 5 }, ctx);
      other.mint({ password });
    `;
    expect(detectRequestState(sf(code))).toEqual([]);
  });
});

describe("header-sensitive", () => {
  it("flags secret fields mirrored into headers (JSON schema and zod meta)", () => {
    const code = `
      const a = { properties: { apiKey: { type: "string", "x-mcp-header": "Key" } } };
      const b = { apiKey: z.string().meta({ "x-mcp-header": "Key" }) };
    `;
    expect(detectSensitiveHeaderMapping(sf(code))).toHaveLength(2);
  });

  it("allows routing fields", () => {
    const code = `const a = { properties: { region: { type: "string", "x-mcp-header": "Region" } } };`;
    expect(detectSensitiveHeaderMapping(sf(code))).toEqual([]);
  });
});

describe("meta-authz", () => {
  const wrap = (body: string) => sf(`import { McpServer } from "@modelcontextprotocol/server";\n${body}`);

  it("flags authorization decisions read from _meta and headers", () => {
    const f = detectUntrustedContextAuthz(
      wrap(`
      server.registerTool("t", { inputSchema: {} }, async (a, ctx) => {
        if (ctx.mcpReq._meta?.role === "admin") return run();
        const tenantId = ctx.http?.req.headers["x-tenant-id"];
        return ctx.http.req.headers.get("x-user-id") ? ok() : no();
      });
    `)
    );
    expect(f).toHaveLength(3);
    expect(f[0].confidence).toBe("medium");
    expect(f[1].confidence).toBe("low");
  });

  it("ignores progress tokens, non-auth headers and non-SDK files", () => {
    const benign = wrap(`
      if (ctx.mcpReq._meta?.progressToken) notify();
      if (req.headers["user-agent"]) log();
      const x = req.headers["content-type"];
      const allow = response.headers.get("x-user-id");
      if (res.headers["x-tenant"]) done();
    `);
    expect(detectUntrustedContextAuthz(benign)).toEqual([]);
    expect(detectUntrustedContextAuthz(sf(`if (req.headers["x-user-id"]) go();`))).toEqual([]);
  });
});

describe("apps-xss", () => {
  const tool = (html: string, extra = "") => sf(`
    server.registerTool("view", { inputSchema: { name: z.string() } }, async ({ name }) => {
      ${extra}
      return { content: [{ type: "resource", resource: { uri: "ui://v", mimeType: "text/html;profile=mcp-app", text: ${html} } }] };
    });
  `);

  it("flags tool input interpolated into HTML", () => {
    const f = detectAppsHtmlXss(tool("`<h1>${name}</h1>`"));
    expect(f).toHaveLength(1);
    expect(f[0].taintChain?.[0]).toContain("name");
  });

  it("follows taint through intermediate variables", () => {
    expect(detectAppsHtmlXss(tool("page", "const page = `<b>${name}</b>`;"))).toHaveLength(1);
  });

  it("accepts escaped or static HTML", () => {
    expect(detectAppsHtmlXss(tool("`<h1>${escapeHtml(name)}</h1>`"))).toEqual([]);
    expect(detectAppsHtmlXss(tool('"<h1>static</h1>"'))).toEqual([]);
  });

  it("ignores non-HTML resources", () => {
    const code = `server.registerTool("t", { inputSchema: { n: z.string() } }, async ({ n }) => ({ content: [{ resource: { mimeType: "text/plain", text: \`\${n}\` } }] }));`;
    expect(detectAppsHtmlXss(sf(code))).toEqual([]);
  });

  it("covers registerResource template variables", () => {
    const code = `server.registerResource("r", new ResourceTemplate("ui://{id}"), {}, async (uri, { id }) => ({ contents: [{ uri: uri.href, mimeType: "text/html", text: \`<p>\${id}</p>\` }] }));`;
    expect(detectAppsHtmlXss(sf(code))).toHaveLength(1);
  });
});

describe("handler discovery for prompts and resources", () => {
  it("taints registerPrompt args and skips extra-only prompts", () => {
    const [a] = findMCPToolHandlers(sf(`server.registerPrompt("p", { argsSchema: { q: z.string() } }, ({ q }) => q);`));
    expect(a.paramNames).toEqual(["q"]);
    const [b] = findMCPToolHandlers(sf(`server.registerPrompt("p", { description: "d" }, (extra) => extra);`));
    expect(b.paramNames).toEqual([]);
  });

  it("taints uri and variables for resources and honours registerAppTool config position", () => {
    const [r] = findMCPToolHandlers(sf(`server.registerResource("r", tpl, {}, async (uri, { id }) => id);`));
    expect(r.paramNames).toEqual(["uri", "id"]);
    const [t] = findMCPToolHandlers(sf(`registerAppTool(server, "t", { inputSchema: { q: z.string() } }, async ({ q }) => q);`));
    expect(t.paramNames).toEqual(["q"]);
  });
});
