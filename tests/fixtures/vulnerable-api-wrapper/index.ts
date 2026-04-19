import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { z } from "zod";

const server = new Server({ name: "vulnerable-api-wrapper", version: "1.0.0" });

// VULNERABILITY: CWE-798 — hardcoded API key
const API_KEY = "sk-1234567890abcdefghijklmnopqrstuv";
const SECRET_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456789";

// VULNERABILITY: CWE-918 — user URL passed directly to fetch
server.tool(
  "fetch_url",
  { url: z.string() },
  async ({ url }) => {
    const resp = await fetch(url);
    const text = await resp.text();
    return { content: [{ type: "text", text }] };
  }
);

// VULNERABILITY: CWE-918 — URL built from user input, no allowlist
server.tool(
  "call_api",
  { endpoint: z.string(), method: z.string() },
  async ({ endpoint, method }) => {
    const resp = await fetch(`https://api.example.com/${endpoint}`, {
      method,
      headers: { Authorization: `Bearer ${API_KEY}` },
    });
    return { content: [{ type: "text", text: await resp.text() }] };
  }
);

// SAFE: hardcoded URL — should NOT trigger SSRF
server.tool(
  "get_status",
  {},
  async () => {
    const resp = await fetch("https://api.example.com/status");
    return { content: [{ type: "text", text: await resp.text() }] };
  }
);
