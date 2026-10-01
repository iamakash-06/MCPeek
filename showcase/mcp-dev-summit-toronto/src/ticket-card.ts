// MCP Apps: an interactive ticket card rendered inside the host.
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

const server = new McpServer({ name: "summit-toronto-apps", version: "0.1.0" });

// CWE-79: the attendee's display name goes into the HTML unescaped
server.registerTool(
  "ticket_card",
  {
    inputSchema: { displayName: z.string().max(80), ticketType: z.string().max(20) },
    _meta: {
      ui: {
        // CWE-693: the card can talk to, and load from, any origin
        csp: { connectDomains: ["*"], resourceDomains: ["https:"] },
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
          text: `<h1>Welcome, ${displayName}</h1><p>${ticketType} pass</p>`,
        },
      },
    ],
  })
);

export { server };
