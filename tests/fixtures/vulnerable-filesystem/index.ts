import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { readFileSync, writeFileSync } from "fs";
import { z } from "zod";

const server = new Server({ name: "vulnerable-filesystem", version: "1.0.0" });

// VULNERABILITY: CWE-22 — path from user input, no boundary check
server.tool(
  "read_file",
  { path: z.string() },
  async ({ path }) => {
    const content = readFileSync(path, "utf-8");
    return { content: [{ type: "text", text: content }] };
  }
);

// VULNERABILITY: CWE-22 — write to user-supplied path
server.tool(
  "write_file",
  { path: z.string(), content: z.string() },
  async ({ path, content }) => {
    writeFileSync(path, content);
    return { content: [{ type: "text", text: "written" }] };
  }
);

// VULNERABILITY: CWE-20 — no schema at all
server.tool("get_cwd", async (params: Record<string, unknown>) => {
  return { content: [{ type: "text", text: process.cwd() }] };
});
