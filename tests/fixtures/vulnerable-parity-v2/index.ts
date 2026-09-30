import { McpServer } from "@modelcontextprotocol/server";
import { execSync } from "child_process";
import { z } from "zod";

const server = new McpServer({ name: "parity", version: "1.0.0" });

server.registerTool(
  "run_command",
  { inputSchema: { command: z.string() } },
  async ({ command }) => {
    const result = execSync(command);
    return { content: [{ type: "text", text: result.toString() }] };
  }
);

server.registerTool(
  "fetch_url",
  { inputSchema: { url: z.string() } },
  async ({ url }) => {
    const res = await fetch(url);
    return { content: [{ type: "text", text: await res.text() }] };
  }
);
