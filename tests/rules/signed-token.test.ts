import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectSignedTokenSecrets } from "../../src/analyzers/rules/signed-token.js";

const scan = (code: string) =>
  detectSignedTokenSecrets(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", `import jwt from "jsonwebtoken";\n${code}`));

describe("signed-token-secret", () => {
  it("flags credentials placed in a signed JWT payload", () => {
    const f = scan(`const t = jwt.sign({ sub: user.id, accessToken: gh.token }, KEY);`);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ rule: "mcp-signed-token-secret", severity: "high" });
    expect(f[0].message).toContain("accessToken");
  });

  it("flags SignJWT payloads", () => {
    expect(scan(`const t = await new SignJWT({ apiKey }).setProtectedHeader({ alg: "HS256" }).sign(KEY);`)).toHaveLength(1);
  });

  it("accepts payloads with no credentials", () => {
    expect(scan(`const t = jwt.sign({ sub: user.id, iss: process.env.ISSUER, exp }, KEY);`)).toEqual([]);
  });

  it("ignores files that do not use a JWT library", () => {
    const f = detectSignedTokenSecrets(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", `sign({ password: p }, k);`));
    expect(f).toEqual([]);
  });
});
