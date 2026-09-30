import { readdirSync, readFileSync } from "fs";
import { join } from "path";
import type { Finding, ScanOptions } from "../types.js";
import { fileKind, isVendoredFile, SKIP_DIRS } from "./coverage.js";

const DEP_FIELDS = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const UNBOUNDED_RE = /^(\*|x|latest|>=?\s*[\d.]+)$/i;

function findManifests(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(join(dir, e.name));
      } else if (e.name === "package.json") {
        out.push(join(dir, e.name));
      }
    }
  };
  walk(root);
  return out;
}

function lineOf(text: string, dep: string): number {
  const idx = text.indexOf(`"${dep}"`);
  return idx < 0 ? 1 : text.slice(0, idx).split("\n").length;
}

function readManifest(file: string): { text: string; pkg: Record<string, any> } | undefined {
  try {
    const text = readFileSync(file, "utf-8");
    return { text, pkg: JSON.parse(text) };
  } catch {
    return undefined;
  }
}

export function scanManifests(root: string, options: ScanOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const files = findManifests(root);
  const localPackages = new Set(files.map((f) => readManifest(f)?.pkg.name).filter((n): n is string => typeof n === "string"));
  for (const file of files) {
    const kind = fileKind(file);
    if (isVendoredFile(file) || (kind === "test" && !options.includeTests)) continue;

    const manifest = readManifest(file);
    if (!manifest) continue;
    const { text, pkg } = manifest;

    for (const field of DEP_FIELDS) {
      for (const [dep, range] of Object.entries((pkg[field] ?? {}) as Record<string, string>)) {
        if (!dep.startsWith("@modelcontextprotocol/") || typeof range !== "string" || localPackages.has(dep)) continue;
        const line = lineOf(text, dep);
        const base = { file, line, column: 1, evidence: `"${dep}": "${range}"`, confidence: "high" as const, ...(kind ? { context: kind } : {}) };

        if (dep === "@modelcontextprotocol/sdk" && field !== "devDependencies") {
          findings.push({
            ...base,
            rule: "mcp-migration-legacy-sdk",
            severity: "info",
            cwe: "CWE-1104",
            message: "Depends on the v1 @modelcontextprotocol/sdk package; the v2 SDK is published as @modelcontextprotocol/server",
            remediation: "Plan the move to @modelcontextprotocol/server and pin an exact version until then.",
          });
        }
        if (UNBOUNDED_RE.test(range.trim()) && !(pkg.workspaces && range.trim() === "*")) {
          findings.push({
            ...base,
            rule: "mcp-migration-unbounded-sdk-range",
            severity: "low",
            cwe: "CWE-1104",
            message: `"${dep}" is not bounded (${range}), so an install can pull a breaking major release`,
            remediation: "Pin an exact version or a caret range below the next major.",
          });
        }
      }
    }
  }
  return findings;
}
