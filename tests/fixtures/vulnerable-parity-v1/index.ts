import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";
import { z } from "zod";

const server = new McpServer({ name: "parity", version: "1.0.0" });

server.tool("run_command", { command: z.string() }, async ({ command }) => {
  const result = execSync(command);
  return { content: [{ type: "text", text: result.toString() }] };
});

server.tool("fetch_url", { url: z.string() }, async ({ url }) => {
  const res = await fetch(url);
  return { content: [{ type: "text", text: await res.text() }] };
});
