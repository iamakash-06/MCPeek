import { McpServer, createRequestStateCodec, inputRequired } from "@modelcontextprotocol/server";
import { z } from "zod";
import { deleteProject, ownsProject } from "./store.js";

const codec = createRequestStateCodec({
  key: Buffer.from(process.env.STATE_KEY!, "hex"),
  bind: (ctx) => `${ctx.mcpReq.method}\0${ctx.http?.authInfo?.clientId ?? ""}`,
});

const server = new McpServer(
  { name: "acme-ops", version: "1.0.0" },
  { requestState: { verify: codec.verify } }
);

server.registerTool(
  "delete_project",
  { inputSchema: { projectId: z.string().max(64) } },
  async ({ projectId }, ctx) => {
    const state = ctx.mcpReq.requestState<{ step: string; projectId: string }>();
    if (!state) {
      if (!ownsProject(ctx.http?.authInfo?.clientId, projectId)) {
        return { isError: true, content: [{ type: "text", text: "not your project" }] };
      }
      return inputRequired({ requestState: await codec.mint({ step: "confirm", projectId }, ctx) });
    }
    await deleteProject(state.projectId);
    return { content: [{ type: "text", text: `deleted ${state.projectId}` }] };
  }
);
