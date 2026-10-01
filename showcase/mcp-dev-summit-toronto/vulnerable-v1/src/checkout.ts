// The team started moving checkout to the v2 SDK. Half of it is migrated, and the
// new v2 primitives are used in ways that open new holes.
import { McpServer, createRequestStateCodec, inputRequired } from "@modelcontextprotocol/server";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { refundTicket, cancelRegistration, ticketPrice } from "./orders.js";

// CWE-321 + CWE-345: key hardcoded, and no bind callback so state can be replayed by anyone
const codec = createRequestStateCodec({ key: "summit-toronto-2026-super-secret-signing-key" });

const server = new McpServer({ name: "summit-toronto-checkout", version: "0.1.0" });

// CWE-807: the caller says it is an organiser in _meta, and we believe it
// CWE-200: payment token mirrored into an HTTP header
server.registerTool(
  "refund_ticket",
  {
    inputSchema: {
      ticketId: z.string().max(40),
      paymentToken: z.string().max(19).meta({ "x-mcp-header": "Payment-Token" }),
    },
  },
  async ({ ticketId, paymentToken }, ctx) => {
    if (ctx.mcpReq._meta?.role === "organiser") {
      await refundTicket(ticketId);
      return { content: [{ type: "text", text: "Refunded without approval" }] };
    }
    // CWE-312: the payment token goes into state that is signed but not encrypted
    return inputRequired({ requestState: await codec.mint({ step: "confirm", ticketId, paymentToken }, ctx) });
  }
);

// CWE-639: ticketId comes out of requestState and reaches a mutating call, and
// nothing checks that the caller owns the registration
server.registerTool(
  "cancel_registration",
  { inputSchema: { reason: z.string().max(200) } },
  async ({ reason }, ctx) => {
    const state = ctx.mcpReq.requestState<{ step: string; ticketId: string }>();
    if (!state) {
      return inputRequired({ requestState: await codec.mint({ step: "confirm", ticketId: "pending" }, ctx) });
    }
    await cancelRegistration(state.ticketId, reason);
    return { content: [{ type: "text", text: `Cancelled ${state.ticketId}` }] };
  }
);

// CWE-807: Mcp-Name header decides the branch, never compared with the body
export function routeByHeader(req: { headers: Record<string, string> }) {
  if (req.headers["mcp-name"] === "refund_ticket") {
    return "finance";
  }
  return "general";
}

// CWE-312: a signed JWT is readable by anyone, and it carries the payment token
export function issueReceipt(attendeeEmail: string, paymentToken: string) {
  return jwt.sign({ sub: attendeeEmail, paymentToken, price: ticketPrice }, process.env.RECEIPT_KEY!);
}

export { server };
