import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectSqlInjection } from "../../src/analyzers/rules/sql-injection.js";

function makeProject(code: string) {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile("test.ts", code);
  return project.getSourceFileOrThrow("test.ts");
}

describe("sql-injection rule", () => {
  it("flags tainted var in template-literal db.query()", () => {
    const sf = makeProject(`
      server.tool("lookup", { id: z.string() }, async ({ id }) => {
        const rows = await db.query(\`SELECT * FROM users WHERE id = '\${id}'\`);
        return { content: [] };
      });
    `);
    const findings = detectSqlInjection(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("mcp-sql-injection");
    expect(findings[0].cwe).toBe("CWE-89");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].taintChain).toBeDefined();
  });

  it("does NOT flag prisma.$queryRaw tagged template (Prisma escapes interpolations)", () => {
    const sf = makeProject(`
      server.tool("findUser", { id: z.string() }, async ({ id }) => {
        return await prisma.$queryRaw\`SELECT * FROM "User" WHERE id = \${id}\`;
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("does NOT flag prisma.$executeRaw tagged template (same Prisma escape rule)", () => {
    const sf = makeProject(`
      server.tool("upd", { id: z.string() }, async ({ id }) => {
        return await prisma.$executeRaw\`UPDATE u SET active = true WHERE id = \${id}\`;
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("flags $queryRawUnsafe call with tainted string", () => {
    const sf = makeProject(`
      server.tool("q", { table: z.string() }, async ({ table }) => {
        return await prisma.$queryRawUnsafe(\`SELECT * FROM \${table}\`);
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(1);
  });

  it("flags string concatenation with DB receiver", () => {
    const sf = makeProject(`
      server.tool("concat", { name: z.string() }, async ({ name }) => {
        return pool.query("SELECT * FROM users WHERE name = '" + name + "'");
      });
    `);
    const findings = detectSqlInjection(sf);
    expect(findings).toHaveLength(1);
  });

  it("flags knex.raw with template literal", () => {
    const sf = makeProject(`
      server.tool("k", { id: z.string() }, async ({ id }) => {
        return knex.raw(\`SELECT * FROM t WHERE id = \${id}\`);
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(1);
  });

  it("does NOT flag parameterised query (placeholder + array)", () => {
    const sf = makeProject(`
      server.tool("safe", { id: z.string() }, async ({ id }) => {
        return db.query("SELECT * FROM users WHERE id = ?", [id]);
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("does NOT flag prisma ORM (findUnique/findMany) — not a raw sink", () => {
    const sf = makeProject(`
      server.tool("orm", { id: z.string() }, async ({ id }) => {
        return prisma.user.findUnique({ where: { id } });
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("does NOT flag query when no tainted input flows in", () => {
    const sf = makeProject(`
      server.tool("static", { foo: z.string() }, async () => {
        return db.query("SELECT * FROM users WHERE deleted = false");
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("does NOT flag generic execute() on non-DB receiver", () => {
    const sf = makeProject(`
      server.tool("notdb", { id: z.string() }, async ({ id }) => {
        return someStream.execute("anything " + id);
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("does NOT trip on child_process.exec (different rule)", () => {
    const sf = makeProject(`
      server.tool("cmd", { id: z.string() }, async ({ id }) => {
        return execSync("ls " + id);
      });
    `);
    // execSync isn't in SQL_SINKS at all
    expect(detectSqlInjection(sf)).toHaveLength(0);
  });

  it("traces taint through an alias to the SQL sink", () => {
    const sf = makeProject(`
      server.tool("alias", { userId: z.string() }, async ({ userId }) => {
        const u = userId;
        const q = u;
        return await db.query(\`SELECT * FROM users WHERE id = '\${q}'\`);
      });
    `);
    const findings = detectSqlInjection(sf);
    expect(findings).toHaveLength(1);
    expect(findings[0].taintChain!.length).toBeGreaterThanOrEqual(3);
  });

  it("flags runQuery() with tainted template literal", () => {
    const sf = makeProject(`
      server.tool("runner", { name: z.string() }, async ({ name }) => {
        return dataSource.runQuery(\`SELECT 1 FROM t WHERE name = '\${name}'\`);
      });
    `);
    expect(detectSqlInjection(sf)).toHaveLength(1);
  });
});
