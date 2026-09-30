import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectRequestStateAuthzGap } from "../../src/analyzers/rules/requeststate-authz.js";

const scan = (code: string, extra = "") => {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("codec.ts", `export const codec = createRequestStateCodec({ key: K${extra} });`);
  return detectRequestStateAuthzGap(project.createSourceFile("t.ts", code));
};

const handler = (body: string) => `
server.registerTool("delete_project", { inputSchema: { projectId: z.string() } }, async ({ projectId }, ctx) => {
${body}
});`;

describe("requeststate-authz-gap", () => {
  it("flags round 2 acting on state after a round-1-only ownership check", () => {
    const f = scan(handler(`
      const state = ctx.mcpReq.requestState<{ projectId: string }>();
      if (!state) {
        if (!owns(ctx.http?.authInfo?.clientId, projectId)) throw new Error("denied");
        return inputRequired({ requestState: await codec.mint({ projectId }, ctx) });
      }
      await deleteProject(state.projectId);
      return { content: [] };`));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: "mcp-requeststate-authz-gap", severity: "high", confidence: "medium" });
    expect(f[0].taintChain?.[0]).toBe("state (requestState)");
  });

  it("follows destructured state and aliases", () => {
    const f = scan(handler(`
      const { projectId: id } = ctx.mcpReq.requestState();
      const target = id;
      await db.projects.delete(target);`));
    expect(f).toHaveLength(1);
  });

  it("accepts an ownership check before the mutation", () => {
    const f = scan(handler(`
      const state = ctx.mcpReq.requestState();
      if (state && !owns(ctx.http?.authInfo?.clientId, state.projectId)) throw new Error("denied");
      await deleteProject(state.projectId);`));
    expect(f).toEqual([]);
  });

  it("accepts an ownership condition around the mutation", () => {
    const f = scan(handler(`
      const state = ctx.mcpReq.requestState();
      if (state.owner === ctx.http?.authInfo?.clientId) await deleteProject(state.projectId);`));
    expect(f).toEqual([]);
  });

  it("accepts the caller identity passed to the mutation", () => {
    const f = scan(handler(`
      const state = ctx.mcpReq.requestState();
      await deleteProject(state.projectId, ctx.http?.authInfo?.clientId);`));
    expect(f).toEqual([]);
  });

  it("ignores non-mutating use of state", () => {
    const f = scan(handler(`
      const state = ctx.mcpReq.requestState();
      return { content: [{ type: "text", text: state.step }] };`));
    expect(f).toEqual([]);
  });

  it("does not fire when any codec binds state to the caller", () => {
    const f = scan(
      handler(`
      const state = ctx.mcpReq.requestState();
      await deleteProject(state.projectId);`),
      `, bind: (c) => c.http?.authInfo?.clientId`
    );
    expect(f).toEqual([]);
  });

  it("does not fire without requestState reads", () => {
    const f = scan(handler(`await deleteProject(projectId);`));
    expect(f).toEqual([]);
  });

  it("lowers confidence when no codec is visible", () => {
    const project = new Project({ useInMemoryFileSystem: true });
    const file = project.createSourceFile("t.ts", handler(`
      const state = ctx.mcpReq.requestState();
      await deleteProject(state.projectId);`));
    expect(detectRequestStateAuthzGap(file)[0].confidence).toBe("low");
  });
});

describe("requeststate-authz-gap fixtures", () => {
  const fixture = (name: string) => {
    const project = new Project({ skipAddingFilesFromTsConfig: true });
    return detectRequestStateAuthzGap(project.addSourceFileAtPath(`tests/fixtures/${name}/index.ts`));
  };

  it("flags the vulnerable server", () => {
    const f = fixture("vulnerable-mrtr-delete");
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(23);
  });

  it("passes the hardened twin", () => {
    expect(fixture("hardened-mrtr-delete")).toEqual([]);
  });
});
