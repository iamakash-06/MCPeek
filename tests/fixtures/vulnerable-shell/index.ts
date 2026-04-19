import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { execSync, spawn } from "child_process";
import { z } from "zod";

const server = new Server({ name: "vulnerable-shell", version: "1.0.0" });

// VULNERABILITY: CWE-78 — command from user input passed directly to execSync
server.tool(
  "run_command",
  { command: z.string() },
  async ({ command }) => {
    const result = execSync(command);
    return { content: [{ type: "text", text: result.toString() }] };
  }
);

// VULNERABILITY: CWE-78 — spawn with user-controlled args
server.tool(
  "execute_script",
  { script: z.string(), args: z.array(z.string()) },
  async ({ script, args }) => {
    const proc = spawn(script, args);
    return { content: [{ type: "text", text: "started" }] };
  }
);

// SAFE: fixed command, only validated args — should NOT trigger
server.tool(
  "list_files",
  { directory: z.string().regex(/^[a-zA-Z0-9_\-./]+$/) },
  async ({ directory }) => {
    const result = execSync(`ls -la`, { cwd: directory });
    return { content: [{ type: "text", text: result.toString() }] };
  }
);
