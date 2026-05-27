import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { scanEnvContent, scanEnvFiles } from "../src/analyzers/env-scanner.js";

describe("env-scanner — scanEnvContent", () => {
  it("flags a known-prefix secret regardless of key name", () => {
    const findings = scanEnvContent(
      `OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr`,
      ".env"
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].rule).toBe("mcp-hardcoded-credential");
    expect(findings[0].cwe).toBe("CWE-798");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].confidence).toBe("high");
    expect(findings[0].line).toBe(1);
    // Value must be redacted, never echoed in full.
    expect(findings[0].message).not.toContain("sk-abc123def456ghi789jkl012mno345pqr");
  });

  it("flags a long opaque value under a credential-named key", () => {
    const findings = scanEnvContent(`DB_PASSWORD=aB7xQ9mL2pR4wS6kT8nV0jH3`, ".env");
    expect(findings).toHaveLength(1);
    expect(findings[0].confidence).toBe("medium");
  });

  it("reports the correct 1-based line number", () => {
    const findings = scanEnvContent(
      `# comment\nFOO=bar\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789`,
      ".env"
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(3);
  });

  it("strips surrounding quotes and a leading export", () => {
    const findings = scanEnvContent(
      `export API_KEY="sk-abc123def456ghi789jkl012mno345pqr"`,
      ".env"
    );
    expect(findings).toHaveLength(1);
  });

  it("ignores comments, blank lines, and short non-secret values", () => {
    const findings = scanEnvContent(
      `# secrets below\n\nPORT=3000\nNODE_ENV=production`,
      ".env"
    );
    expect(findings).toHaveLength(0);
  });

  it("does NOT flag placeholders or variable interpolation", () => {
    const findings = scanEnvContent(
      `API_KEY=your-key-here\nSECRET=<REPLACE_ME>\nTOKEN=\${OTHER_VAR}`,
      ".env"
    );
    expect(findings).toHaveLength(0);
  });
});

describe("env-scanner — scanEnvFiles discovery", () => {
  let dir: string;
  afterEach(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("finds .env files and skips node_modules", () => {
    dir = mkdtempSync(join(tmpdir(), "mcpeek-env-"));
    writeFileSync(
      join(dir, ".env"),
      "OPENAI_API_KEY=sk-abc123def456ghi789jkl012mno345pqr"
    );
    writeFileSync(join(dir, ".env.production"), "PORT=8080");
    mkdirSync(join(dir, "node_modules", "pkg"), { recursive: true });
    writeFileSync(
      join(dir, "node_modules", "pkg", ".env"),
      "VENDOR_SECRET=sk-vendor123456789012345678901234"
    );

    const findings = scanEnvFiles(dir);
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toContain(".env");
    expect(findings[0].file).not.toContain("node_modules");
  });
});
