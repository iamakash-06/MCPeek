import { readdirSync } from "fs";
import { extname, join } from "path";
import type { Coverage } from "../types.js";

const OTHER_LANGUAGES: Record<string, string> = {
  ".py": "Python",
  ".go": "Go",
  ".cs": "C#",
  ".java": "Java",
  ".kt": "Kotlin",
  ".rs": "Rust",
};

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "vendor", "target", "venv", ".venv", "__pycache__"]);

const VENDORED_RE = /(^|\/)(vendor|vendored|third[_-]party|generated|__generated__)\//;
const GENERATED_FILE_RE = /(\.generated|\.gen|spec\.types)\.(ts|js)$/;

export function isVendoredFile(fp: string): boolean {
  return VENDORED_RE.test(fp) || GENERATED_FILE_RE.test(fp);
}

export function countUnsupportedSources(root: string): Record<string, number> {
  const counts: Record<string, number> = {};
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
      } else {
        const lang = OTHER_LANGUAGES[extname(e.name)];
        if (lang) counts[lang] = (counts[lang] ?? 0) + 1;
      }
    }
  };
  walk(root);
  return counts;
}

export function coverageWarnings(c: Coverage): string[] {
  const warnings: string[] = [];
  const unsupported = Object.entries(c.unsupported).sort((a, b) => b[1] - a[1]);
  const unsupportedTotal = unsupported.reduce((s, [, n]) => s + n, 0);
  if (unsupportedTotal > 0 && unsupportedTotal >= c.filesAnalyzed) {
    warnings.push(
      `Most source files are not TypeScript/JavaScript and were not analyzed (${unsupported.map(([l, n]) => `${l}: ${n}`).join(", ")}).`
    );
  }
  return warnings;
}
