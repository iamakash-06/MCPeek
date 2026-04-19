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
}

export interface AuditResult {
  target: Target;
  scan: ScanResult;
}

export type OutputFormat = "json" | "markdown" | "sarif";
