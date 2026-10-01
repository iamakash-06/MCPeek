// MCP Apps: an interactive ticket card rendered inside the host.
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

const escapeHtml = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const server = new McpServer({ name: "summit-toronto-apps", version: "1.0.0" });

server.registerTool(
  "ticket_card",
  {
    inputSchema: { displayName: z.string().max(80), ticketType: z.enum(["early", "regular", "workshop"]) },
    _meta: {
      ui: {
        // Exact origins only.
        csp: { connectDomains: ["https://api.mcpdevsummit.example"], resourceDomains: ["https://cdn.mcpdevsummit.example"] },
      },
    },
  },
  async ({ displayName, ticketType }) => ({
    content: [
      {
        type: "resource",
        resource: {
          uri: "ui://summit/ticket",
          mimeType: "text/html;profile=mcp-app",
          text: `<h1>Welcome, ${escapeHtml(displayName)}</h1><p>${escapeHtml(ticketType)} pass</p>`,
        },
      },
    ],
  })
);

export { server };
