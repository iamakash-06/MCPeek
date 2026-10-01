import { createRequestStateCodec } from "@modelcontextprotocol/server";

// One shared key from the environment, so every instance can verify state minted by another.
// bind() ties each state to the method and the authenticated caller, so it cannot be replayed.
export const codec = createRequestStateCodec({
  key: Buffer.from(process.env.REQUEST_STATE_KEY!, "hex"),
  bind: (ctx) => `${ctx.mcpReq.method}\0${ctx.http?.authInfo?.clientId ?? ""}`,
});
