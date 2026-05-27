export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface Finding {
  rule: string;
  severity: Severity;
  cwe: string;
  file: string;
  line: number;
  column: number;
  message: string;
  evidence: string;
  remediation: string;
  confidence: Confidence;
  /** Step-by-step path from handler param to dangerous sink, e.g.
   *  ["cmd (handler param)", "command (line 3)", "execSync() (line 5)"]
   *  Only present for taint-tracked rules (command-injection, path-traversal, ssrf).
   */
  taintChain?: string[];
}

export interface ScanResult {
  target: string;
  scannedAt: string;
  language: "typescript" | "javascript" | "unknown";
  filesScanned: number;
  findings: Finding[];
  score: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface Target {
  name: string;
  url: string;
  stars: number;
  language: string;
  category: string;
  lastCommit: string;
}

export interface ScanOptions {
  rules?: string[];
  verify?: boolean;
  failOn?: Severity;
  ci?: boolean;
  /** Extra project-local function names that register MCP tools (limitation L7). */
  extraRegistrations?: string[];
  /** Treat the handler's second (context) parameter as tainted too (limitation L6). */
  taintContextParam?: boolean;
  /** Scan example/test/demo files normally excluded by the filter (limitation L15). */
  includeTests?: boolean;
}

export interface AuditResult {
  target: Target;
  scan: ScanResult;
}

export type OutputFormat = "json" | "markdown" | "sarif";
