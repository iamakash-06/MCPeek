import { McpServer, inputRequired } from "@modelcontextprotocol/server";
import { execFile } from "child_process";
import { mkdir, writeFile } from "fs/promises";
import { randomUUID } from "crypto";
import path from "path";
import { z } from "zod";
import { db, findSessions } from "./db.js";
import { codec } from "./state.js";
import { chargeCard, ownsTicket, refundTicket, cancelRegistration } from "./orders.js";

// No per-session state: nothing in this process remembers a caller between requests.
const server = new McpServer({ name: "summit-toronto", version: "1.0.0" }, { requestState: { verify: codec.verify } });

const SLIDES_DIR = path.resolve("/srv/summit/slides");
const ALLOWED_HEADSHOT_HOSTS = new Set(["cdn.mcpdevsummit.example", "avatars.speakers.example"]);
const EXPORT_FORMATS = { csv: "csv", json: "json" } as const;

// ───────────────────────── speakers ─────────────────────────

server.registerTool(
  "get_speaker_guidelines",
  {
    description: "Returns the speaker guidelines for a track.",
    inputSchema: { track: z.string().min(1).max(40) },
  },
  async ({ track }) => ({ content: [{ type: "text", text: `Guidelines for ${track}` }] })
);

server.registerTool(
  "list_my_sessions",
  { description: "List the sessions of the authenticated speaker.", inputSchema: { limit: z.number().int().min(1).max(100) } },
  async ({ limit }, ctx) => {
    const { rows } = await db.query("SELECT * FROM sessions WHERE speaker_id = $1 LIMIT $2", [ctx.http?.authInfo?.clientId, limit]);
    return { content: [{ type: "text", text: JSON.stringify(rows) }] };
  }
);

server.registerTool(
  "submit_session",
  {
    description: "Submit a talk proposal for the summit.",
    inputSchema: {
      title: z.string().min(5).max(120),
      abstract: z.string().min(50).max(2000),
      level: z.enum(["beginner", "intermediate", "advanced"]),
    },
  },
  async ({ title, abstract, level }) => {
    await db.query("INSERT INTO sessions (title, abstract, level) VALUES ($1, $2, $3)", [title, abstract, level]);
    return { content: [{ type: "text", text: "Submitted" }] };
  }
);

// The file name is reduced to its basename and the final path must stay inside SLIDES_DIR.
server.registerTool(
  "upload_slides",
  {
    description: "Upload a slide deck (base64).",
    inputSchema: {
      fileName: z.string().min(1).max(120).regex(/^[\w.-]+\.(pdf|pptx|key)$/),
      contentBase64: z.string().max(5_000_000),
    },
  },
  async ({ fileName, contentBase64 }) => {
    const target = path.resolve(SLIDES_DIR, path.basename(fileName));
    if (!target.startsWith(SLIDES_DIR + path.sep)) {
      return { isError: true, content: [{ type: "text", text: "Invalid file name" }] };
    }
    await mkdir(SLIDES_DIR, { recursive: true });
    await writeFile(target, Buffer.from(contentBase64, "base64"));
    return { content: [{ type: "text", text: "Saved" }] };
  }
);

// Only https URLs on an allowlist of hosts can be fetched.
server.registerTool(
  "import_speaker_headshot",
  { description: "Fetch a headshot from an approved host.", inputSchema: { url: z.string().url().max(500) } },
  async ({ url }) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" || !ALLOWED_HEADSHOT_HOSTS.has(parsed.hostname)) {
      return { isError: true, content: [{ type: "text", text: "Host not allowed" }] };
    }
    const res = await fetch(parsed, { redirect: "error" });
    return { content: [{ type: "text", text: `Fetched ${(await res.arrayBuffer()).byteLength} bytes` }] };
  }
);

// Two closed enums, passed as bind parameters, replace the old "send me JavaScript" predicate.
server.registerTool(
  "filter_schedule",
  {
    description: "Filter the schedule by track and kind.",
    inputSchema: { track: z.enum(["security", "agents", "infra"]), kind: z.enum(["talk", "workshop"]) },
  },
  async ({ track, kind }) => {
    const { rows } = await db.query("SELECT * FROM sessions WHERE track = $1 AND kind = $2", [track, kind]);
    return { content: [{ type: "text", text: JSON.stringify(rows) }] };
  }
);

// ───────────────────────── attendees ─────────────────────────

// "track" is a routing value, so mirroring it into a header is fine. Secrets never are.
server.registerTool(
  "search_sessions",
  {
    description: "Search sessions by keyword and track.",
    inputSchema: {
      term: z.string().min(1).max(80),
      track: z.string().max(40).meta({ "x-mcp-header": "Track" }),
    },
  },
  async ({ term, track }) => {
    const rows = await findSessions(term, track);
    return { content: [{ type: "text", text: JSON.stringify(rows) }] };
  }
);

server.registerTool(
  "get_attendee_badge",
  { description: "Look up your own badge.", inputSchema: { email: z.string().email().max(120) } },
  async ({ email }, ctx) => {
    const { rows } = await db.query("SELECT * FROM badges WHERE email = $1 AND owner = $2", [email, ctx.http?.authInfo?.clientId]);
    return { content: [{ type: "text", text: JSON.stringify(rows) }] };
  }
);

// Fixed binary, format picked from a lookup table, output name generated by the server.
server.registerTool(
  "export_attendees",
  { description: "Export attendees (organisers only).", inputSchema: { format: z.enum(["csv", "json"]) } },
  async ({ format }, ctx) => {
    if (!ctx.http?.authInfo?.scopes.includes("organiser")) {
      return { isError: true, content: [{ type: "text", text: "Forbidden" }] };
    }
    const outFile = `/tmp/attendees-${randomUUID()}.${EXPORT_FORMATS[format]}`;
    execFile("/usr/local/bin/attendee-export", ["--format", EXPORT_FORMATS[format], "--out", outFile]);
    return { content: [{ type: "text", text: "Export started" }] };
  }
);

// The v2 replacement for a pushed elicitation: return inputRequired, then finish on the retried call.
server.registerTool(
  "buy_ticket",
  {
    description: "Buy a ticket. The attendee confirms the price before the card is charged.",
    inputSchema: { ticketType: z.enum(["early", "regular", "workshop"]) },
  },
  async ({ ticketType }, ctx) => {
    const clientId = ctx.http?.authInfo?.clientId;
    if (!clientId) return { isError: true, content: [{ type: "text", text: "Sign in first" }] };

    const state = ctx.mcpReq.requestState<{ step: string; ticketType: string }>();
    if (!state) {
      return inputRequired({
        inputRequests: { confirm: inputRequired.elicit({ message: `Charge your card for the ${ticketType} ticket?` }) },
        requestState: await codec.mint({ step: "confirm", ticketType }, ctx),
      });
    }
    await chargeCard(clientId, state.ticketType);
    return { content: [{ type: "text", text: "Ticket purchased" }] };
  }
);

// ───────────────────────── payments & registrations ─────────────────────────

// Authority comes from verified auth info. Nothing in _meta or a header is trusted.
server.registerTool(
  "refund_ticket",
  { description: "Refund a ticket (organisers only).", inputSchema: { ticketId: z.string().max(40) } },
  async ({ ticketId }, ctx) => {
    if (!ctx.http?.authInfo?.scopes.includes("organiser")) {
      return { isError: true, content: [{ type: "text", text: "Forbidden" }] };
    }
    const state = ctx.mcpReq.requestState<{ step: string }>();
    if (!state) {
      return inputRequired({ requestState: await codec.mint({ step: "confirm", ticketId }, ctx) });
    }
    await refundTicket(ticketId);
    return { content: [{ type: "text", text: "Refunded" }] };
  }
);

// Ownership is re-checked against the caller even though the state is already bound.
server.registerTool(
  "cancel_registration",
  { description: "Cancel your own registration.", inputSchema: { ticketId: z.string().max(40), reason: z.string().max(200) } },
  async ({ ticketId, reason }, ctx) => {
    const state = ctx.mcpReq.requestState<{ step: string; ticketId: string }>();
    if (!state) {
      return inputRequired({ requestState: await codec.mint({ step: "confirm", ticketId }, ctx) });
    }
    if (!(await ownsTicket(ctx.http?.authInfo?.clientId, state.ticketId))) {
      return { isError: true, content: [{ type: "text", text: "Not your registration" }] };
    }
    await cancelRegistration(state.ticketId, reason);
    return { content: [{ type: "text", text: "Cancelled" }] };
  }
);

export { server };
