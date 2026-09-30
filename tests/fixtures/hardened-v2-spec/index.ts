import { McpServer, createRequestStateCodec, inputRequired } from "@modelcontextprotocol/server";
import { z } from "zod";

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const codec = createRequestStateCodec({
  key: process.env.REQUEST_STATE_KEY!,
  bind: (ctx) => `${ctx.mcpReq.method}\0${ctx.http?.authInfo?.clientId ?? ""}`,
});

const server = new McpServer({ name: "hardened-v2-spec", version: "1.0.0" });

server.registerTool(
  "deploy",
  {
    inputSchema: {
      env: z.string().max(32),
      region: z.string().max(16).meta({ "x-mcp-header": "Region" }),
    },
  },
  async ({ env, region }, ctx) => {
    if (ctx.http?.authInfo?.scopes.includes("admin")) {
      return { content: [{ type: "text", text: "skipped approval" }] };
    }
    return inputRequired({ requestState: await codec.mint({ step: "confirm", env, region }, ctx) });
  }
);

server.registerTool(
  "profile_card",
  { inputSchema: { name: z.string().max(64) } },
  async ({ name }) => ({
    content: [
      {
        type: "resource",
        resource: {
          uri: "ui://profile",
          mimeType: "text/html;profile=mcp-app",
          text: `<h1>${escapeHtml(name)}</h1>`,
        },
      },
    ],
  })
);
