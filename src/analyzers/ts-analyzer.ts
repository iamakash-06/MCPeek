import { Project } from "ts-morph";
import { existsSync } from "fs";
import { join } from "path";
import type { Coverage, Finding, ScanOptions } from "../types.js";
import { countUnsupportedSources, coverageWarnings, isVendoredFile } from "./coverage.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "./mcp-handler.js";
import { detectCommandInjection } from "./rules/command-injection.js";
import { detectMissingInputValidation } from "./rules/input-validation.js";
import { detectHardcodedCredentials } from "./rules/credential-hardcoding.js";
import { detectPathTraversal } from "./rules/path-traversal.js";
import { detectSSRF } from "./rules/ssrf.js";
import { detectWeakSchemaBounds } from "./rules/weak-schema-bounds.js";
import { detectToolPoisoning } from "./rules/tool-poisoning.js";
import { detectSqlInjection } from "./rules/sql-injection.js";
import { detectCodeInjection } from "./rules/code-injection.js";
import { detectRequestState } from "./rules/request-state.js";
import { detectSensitiveHeaderMapping } from "./rules/header-sensitive.js";
import { detectUntrustedContextAuthz } from "./rules/untrusted-context.js";
import { detectAppsHtmlXss } from "./rules/apps-xss.js";

export type RuleName =
  | "command-injection"
  | "input-validation"
  | "credential-hardcoding"
  | "path-traversal"
  | "ssrf"
  | "weak-schema-bounds"
  | "tool-poisoning"
  | "sql-injection"
  | "code-injection"
  | "request-state"
  | "header-sensitive"
  | "meta-authz"
  | "apps-xss";

export const ALL_RULES: RuleName[] = [
  "command-injection",
  "input-validation",
  "credential-hardcoding",
  "path-traversal",
  "ssrf",
  "weak-schema-bounds",
  "tool-poisoning",
  "sql-injection",
  "code-injection",
  "request-state",
  "header-sensitive",
  "meta-authz",
  "apps-xss",
];

export interface AnalyzeResult {
  findings: Finding[];
  filesScanned: number;
  warnings: string[];
  coverage: Coverage;
}

const SDK_IMPORT_RE = /from\s+["']@modelcontextprotocol\/(sdk|server)/;

export async function analyzeTypeScript(
  projectRoot: string,
  options: ScanOptions = {}
): Promise<AnalyzeResult> {
  const tsConfig = findTsConfig(projectRoot);

  const fileFilter = (f: ReturnType<Project["getSourceFiles"]>[0]) => {
    const fp = f.getFilePath();
    return (
      !fp.includes("node_modules") &&
      !fp.includes("/dist/") &&
      !fp.includes("/build/") &&
      !fp.endsWith(".d.ts") &&
      !isVendoredFile(fp) &&
      // L15: example/test files are skipped by default, but a shipped vulnerable
      // example server can be a real risk — --include-tests opts them back in.
      (options.includeTests || !isTestFile(fp))
    );
  };

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

  const skipped = { tests: 0, vendored: 0 };
  const countSkipped = (files: ReturnType<Project["getSourceFiles"]>) => {
    for (const f of files) {
      const fp = f.getFilePath();
      if (fp.includes("node_modules") || fp.includes("/dist/") || fp.includes("/build/") || fp.endsWith(".d.ts")) continue;
      if (isVendoredFile(fp)) skipped.vendored++;
      else if (!options.includeTests && isTestFile(fp)) skipped.tests++;
    }
  };

  let sourceFiles = project.getSourceFiles().filter(fileFilter);
  countSkipped(project.getSourceFiles());

  // Project-references pattern: root tsconfig has `"files":[]` + `"references":[...]`.
  // ts-morph reads the root config, sees an empty file list, and adds nothing —
  // it does not follow project references. Detect this by checking for zero files
  // after loading a tsconfig, then fall back to glob so these repos are fully scanned.
  if (sourceFiles.length === 0 && tsConfig) {
    const fallback = new Project({ useInMemoryFileSystem: false });
    fallback.addSourceFilesAtPaths([
      join(projectRoot, "**/*.ts"),
      join(projectRoot, "**/*.js"),
    ]);
    sourceFiles = fallback.getSourceFiles().filter(fileFilter);
    skipped.tests = skipped.vendored = 0;
    countSkipped(fallback.getSourceFiles());
  }

  const activeRules: RuleName[] = options.rules
    ? (options.rules.filter((r) => ALL_RULES.includes(r as RuleName)) as RuleName[])
    : ALL_RULES;

  const handlerOptions: HandlerScanOptions = {
    extraRegistrations: options.extraRegistrations,
    taintContextParam: options.taintContextParam,
  };

  const allFindings: Finding[] = [];
  let importsSdk = false;
  let handlersEntered = 0;

  for (const sourceFile of sourceFiles) {
    importsSdk ||= SDK_IMPORT_RE.test(sourceFile.getFullText());
    try {
      handlersEntered += findMCPToolHandlers(sourceFile, handlerOptions).length;
    } catch {
      // Skip files that fail to parse
    }
    for (const rule of activeRules) {
      try {
        allFindings.push(...runRule(rule, sourceFile, handlerOptions));
      } catch {
        // Skip files that fail to parse
      }
    }
  }

  const blind = importsSdk && handlersEntered === 0;
  const coverage: Coverage = {
    assessed: sourceFiles.length > 0 && !blind,
    filesAnalyzed: sourceFiles.length,
    skipped,
    unsupported: countUnsupportedSources(projectRoot),
    handlers: handlersEntered,
  };

  const warnings = [
    ...(blind
      ? [
          "MCP SDK imported but no tool handlers were detected; taint rules did not run. Tools may be registered through a wrapper, so try --registrations <name>.",
        ]
      : []),
    ...coverageWarnings(coverage),
  ];

  return {
    findings: deduplicateFindings(allFindings),
    filesScanned: sourceFiles.length,
    warnings,
    coverage,
  };
}

function runRule(
  rule: RuleName,
  sourceFile: ReturnType<Project["getSourceFiles"]>[0],
  handlerOptions: HandlerScanOptions
): Finding[] {
  switch (rule) {
    case "command-injection":
      return detectCommandInjection(sourceFile, handlerOptions);
    case "input-validation":
      return detectMissingInputValidation(sourceFile);
    case "credential-hardcoding":
      return detectHardcodedCredentials(sourceFile);
    case "path-traversal":
      return detectPathTraversal(sourceFile, handlerOptions);
    case "ssrf":
      return detectSSRF(sourceFile, handlerOptions);
    case "weak-schema-bounds":
      return detectWeakSchemaBounds(sourceFile);
    case "tool-poisoning":
      return detectToolPoisoning(sourceFile);
    case "sql-injection":
      return detectSqlInjection(sourceFile, handlerOptions);
    case "code-injection":
      return detectCodeInjection(sourceFile, handlerOptions);
    case "request-state":
      return detectRequestState(sourceFile);
    case "header-sensitive":
      return detectSensitiveHeaderMapping(sourceFile);
    case "meta-authz":
      return detectUntrustedContextAuthz(sourceFile);
    case "apps-xss":
      return detectAppsHtmlXss(sourceFile, handlerOptions);
  }
}

function isTestFile(fp: string): boolean {
  return (
    // Unit / integration tests
    fp.endsWith(".test.ts") ||
    fp.endsWith(".test.js") ||
    fp.endsWith(".spec.ts") ||
    fp.endsWith(".spec.js") ||
    fp.includes("/__tests__/") ||
    fp.includes("/test/") ||
    fp.includes("/tests/") ||
    fp.includes("/fixtures/") ||
    fp.includes("/mocks/") ||
    fp.includes("/mock/") ||
    fp.endsWith("mocks.ts") ||
    fp.endsWith("mock.ts") ||
    fp.endsWith("fixtures.ts") ||
    // Documentation examples and guides — intentionally simplified code that
    // does not follow production best-practices (e.g. missing Zod schemas)
    fp.endsWith(".examples.ts") ||
    fp.endsWith(".examples.js") ||
    fp.includes("/examples/") ||
    fp.includes("/example/") ||
    fp.includes("/guides/") ||
    fp.includes("/guide/") ||
    fp.includes("/demo/") ||
    fp.includes("/demos/") ||
    fp.includes("/samples/") ||
    fp.includes("/sample/")
  );
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
  const weakKeys = new Set(
    findings.filter((f) => f.rule === "mcp-requeststate-weak-key").map((f) => `${f.file}:${f.line}`)
  );
  return findings.filter((f) => {
    if (f.rule === "mcp-hardcoded-credential" && weakKeys.has(`${f.file}:${f.line}`)) return false;
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
