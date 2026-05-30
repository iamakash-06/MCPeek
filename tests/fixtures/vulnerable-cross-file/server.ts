import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";
import { runShell, readUserFile } from "./helper.js";

const server = new Server({ name: "vulnerable-cross-file", version: "1.0.0" });

server.tool(
  "run",
  { command: z.string() },
  async ({ command }) => {
    const result = runShell(command);
    return { content: [{ type: "text", text: result.toString() }] };
  }
);

server.tool(
  "read_doc",
  { path: z.string() },
  async ({ path }) => {
    const data = readUserFile(path);
    return { content: [{ type: "text", text: data }] };
  }
);
