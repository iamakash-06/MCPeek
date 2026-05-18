/**
 * Shared utility: extracts a code snippet around a line number for use as
 * finding evidence in security reports.
 */

import { SourceFile } from "ts-morph";

/**
 * Returns `context` lines before and after `lineNum` from `sourceFile`,
 * each prefixed with its line number. Used as the `evidence` field in findings.
 */
export function extractSnippet(
  sourceFile: SourceFile,
  lineNum: number,
  context: number
): string {
  const lines = sourceFile.getFullText().split("\n");
  const start = Math.max(0, lineNum - context - 1);
  const end = Math.min(lines.length, lineNum + context);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}: ${l}`)
    .join("\n");
}
