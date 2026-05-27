/**
 * Scans committed dotenv files (.env, .env.local, .env.production, …) for
 * hardcoded credentials. Addresses limitation L12: the TypeScript analyzer only
 * reads .ts/.js, so a secret sitting in a checked-in .env is otherwise invisible.
 *
 * Reuses the same value/name heuristics as the credential-hardcoding AST rule so
 * findings stay consistent (rule: mcp-hardcoded-credential, CWE-798).
 */

import { readFileSync, readdirSync, statSync } from "fs";
import { basename, join } from "path";
import type { Finding } from "../types.js";
import {
  CREDENTIAL_VALUE_PATTERNS,
  MIN_SUSPICIOUS_LENGTH,
  isPlaceholder,
} from "./rules/credential-hardcoding.js";

// Env keys are typically SCREAMING_SNAKE (DB_PASSWORD, API_KEY), so the shared
// \b-anchored identifier pattern misses words glued by underscores. Match the
// credential word anywhere in the key instead.
const ENV_KEY_PATTERN =
  /(api[_-]?key|apikey|secret|token|password|passwd|auth[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|bearer|credential)/i;

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "coverage",
]);

// .env, .env.local, .env.production, env.example is still scanned but its
// placeholder-style values are filtered out below.
const ENV_FILE_RE = /^\.env(\..+)?$/;

/** Pure core: extract credential findings from the contents of one dotenv file. */
export function scanEnvContent(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) return;

    const withoutExport = line.replace(/^export\s+/, "");
    const eq = withoutExport.indexOf("=");
    if (eq <= 0) return;

    const key = withoutExport.slice(0, eq).trim();
    let value = withoutExport.slice(eq + 1).trim();

    // Strip a trailing inline comment on unquoted values, then surrounding quotes.
    const quoted = /^(['"])(.*)\1$/.exec(value);
    if (quoted) {
      value = quoted[2];
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }

    if (value.length === 0) return;
    // Variable interpolation (KEY=${OTHER}) is a reference, not a literal secret.
    if (/\$\{?\w+/.test(value)) return;
    if (isPlaceholder(value)) return;

    const isKnownPattern = CREDENTIAL_VALUE_PATTERNS.some((p) => p.test(value));
    const nameLooksSecret = ENV_KEY_PATTERN.test(key);

    if (!isKnownPattern && !(nameLooksSecret && value.length >= MIN_SUSPICIOUS_LENGTH)) {
      return;
    }

    const lineNum = idx + 1;
    const redacted =
      value.length > 10 ? `${value.slice(0, 6)}...${value.slice(-4)}` : "***";

    findings.push({
      rule: "mcp-hardcoded-credential",
      severity: "high",
      cwe: "CWE-798",
      file: filePath,
      line: lineNum,
      column: eq + 2,
      message: `Hardcoded credential in dotenv key "${key}" (value: ${redacted})`,
      evidence: `${key}=${redacted}`,
      remediation:
        "Do not commit .env files containing real secrets. Add them to .gitignore, rotate the exposed credential, and load it from the deployment environment instead.",
      confidence: isKnownPattern ? "high" : "medium",
    });
  });

  return findings;
}

/** Walk the repo, find dotenv files, and scan each one. */
export function scanEnvFiles(root: string): Finding[] {
  const findings: Finding[] = [];
  for (const filePath of findEnvFiles(root)) {
    try {
      findings.push(...scanEnvContent(readFileSync(filePath, "utf-8"), filePath));
    } catch {
      // Unreadable file — skip rather than fail the whole scan.
    }
  }
  return findings;
}

function findEnvFiles(dir: string, depth = 0): string[] {
  if (depth > 6) return [];
  const found: string[] = [];

  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }

  for (const entry of entries) {
    const full = join(dir, entry);
    let isDir = false;
    try {
      isDir = statSync(full).isDirectory();
    } catch {
      continue;
    }

    if (isDir) {
      if (SKIP_DIRS.has(entry)) continue;
      found.push(...findEnvFiles(full, depth + 1));
    } else if (ENV_FILE_RE.test(basename(entry))) {
      found.push(full);
    }
  }

  return found;
}
