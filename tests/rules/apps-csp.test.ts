import { describe, it, expect } from "vitest";
import { Project } from "ts-morph";
import { detectAppsWildcardCsp } from "../../src/analyzers/rules/apps-csp.js";

const scan = (code: string) => detectAppsWildcardCsp(new Project({ useInMemoryFileSystem: true }).createSourceFile("t.ts", code));

describe("apps-wildcard-csp", () => {
  it("flags wildcard and scheme-only sources", () => {
    for (const src of ["*", "https://*", "https:", "http://*", "wss:"]) {
      const f = scan(`const r = { _meta: { ui: { csp: { connectDomains: ["${src}"] } } } };`);
      expect(f, src).toHaveLength(1);
      expect(f[0]).toMatchObject({ rule: "mcp-apps-wildcard-csp", severity: "medium" });
    }
  });

  it("resolves a domain list passed by reference and snake_case keys", () => {
    expect(scan(`const D = ["*"];\nconst c = { resourceDomains: D };`)).toHaveLength(1);
    expect(scan(`const c = { connect_domains: ["https://*"] };`)).toHaveLength(1);
  });

  it("accepts exact origins and subdomain wildcards", () => {
    expect(scan(`const c = { connectDomains: ["https://api.example.com", "https://*.mapbox.com"], resourceDomains: ["blob:"] };`)).toEqual([]);
  });
});
