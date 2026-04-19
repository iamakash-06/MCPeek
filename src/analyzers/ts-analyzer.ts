import { Project } from "ts-morph";
import { existsSync } from "fs";
import { join } from "path";
import type { Finding, ScanOptions } from "../types.js";
import { detectCommandInjection } from "./rules/command-injection.js";
import { detectMissingInputValidation } from "./rules/input-validation.js";
import { detectHardcodedCredentials } from "./rules/credential-hardcoding.js";
import { detectPathTraversal } from "./rules/path-traversal.js";
import { detectSSRF } from "./rules/ssrf.js";

export type RuleName =
  | "command-injection"
  | "input-validation"
  | "credential-hardcoding"
  | "path-traversal"
  | "ssrf";

export const ALL_RULES: RuleName[] = [
  "command-injection",
  "input-validation",
  "credential-hardcoding",
  "path-traversal",
  "ssrf",
];

export interface AnalyzeResult {
  findings: Finding[];
  filesScanned: number;
}

export async function analyzeTypeScript(
  projectRoot: string,
  options: ScanOptions = {}
): Promise<AnalyzeResult> {
  const tsConfig = findTsConfig(projectRoot);

  let project: Project;

  if (tsConfig) {
    project = new Project({ tsConfigFilePath: tsConfig, skipAddingFilesFromTsConfig: false });
  } else {
    project = new Project({ useInMemoryFileSystem: false });
    project.addSourceFilesAtPaths([
      join(projectRoot, "**/*.ts"),
      join(projectRoot, "**/*.js"),
    ]);
  }

  const sourceFiles = project.getSourceFiles().filter((f) => {
    const fp = f.getFilePath();
    return (
      !fp.includes("node_modules") &&
      !fp.includes("/dist/") &&
      !fp.includes("/build/") &&
      !fp.endsWith(".d.ts")
    );
  });

  const activeRules: RuleName[] = options.rules
    ? (options.rules.filter((r) => ALL_RULES.includes(r as RuleName)) as RuleName[])
    : ALL_RULES;

  const allFindings: Finding[] = [];

  for (const sourceFile of sourceFiles) {
    for (const rule of activeRules) {
      try {
        allFindings.push(...runRule(rule, sourceFile));
      } catch {
        // Skip files that fail to parse
      }
    }
  }

  return {
    findings: deduplicateFindings(allFindings),
    filesScanned: sourceFiles.length,
  };
}

function runRule(
  rule: RuleName,
  sourceFile: ReturnType<Project["getSourceFiles"]>[0]
): Finding[] {
  switch (rule) {
    case "command-injection":
      return detectCommandInjection(sourceFile);
    case "input-validation":
      return detectMissingInputValidation(sourceFile);
    case "credential-hardcoding":
      return detectHardcodedCredentials(sourceFile);
    case "path-traversal":
      return detectPathTraversal(sourceFile);
    case "ssrf":
      return detectSSRF(sourceFile);
  }
}

function findTsConfig(root: string): string | undefined {
  for (const name of ["tsconfig.json", "tsconfig.build.json"]) {
    const p = join(root, name);
    if (existsSync(p)) return p;
  }
  return undefined;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
