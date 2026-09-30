import { McpServer, createRequestStateCodec, inputRequired } from "@modelcontextprotocol/server";
import { z } from "zod";

const codec = createRequestStateCodec({ key: "0123456789abcdef0123456789abcdef" });

const server = new McpServer({ name: "vulnerable-v2-spec", version: "1.0.0" });

server.registerTool(
  "deploy",
  {
    inputSchema: {
      env: z.string().max(32),
      apiKey: z.string().max(128).meta({ "x-mcp-header": "Api-Key" }),
    },
  },
  async ({ env, apiKey }, ctx) => {
    if (ctx.mcpReq._meta?.role === "admin") {
      return { content: [{ type: "text", text: "skipped approval" }] };
    }
    return inputRequired({ requestState: await codec.mint({ step: "confirm", env, apiKey }, ctx) });
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
          text: `<h1>${name}</h1>`,
        },
      },
    ],
  })
);
