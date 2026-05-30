import { SourceFile, SyntaxKind } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findTaintedReaching } from "../taint-match.js";
import { findMCPToolHandlers, type HandlerScanOptions } from "../mcp-handler.js";
import { extractSnippet } from "../snippet.js";

const FS_SINKS = new Set([
  "readFile",
  "readFileSync",
  "writeFile",
  "writeFileSync",
  "appendFile",
  "appendFileSync",
  "createReadStream",
  "createWriteStream",
  "open",
  "openSync",
  "unlink",
  "unlinkSync",
  "rmdir",
  "rmdirSync",
  "mkdir",
  "mkdirSync",
  "stat",
  "statSync",
  "lstat",
  "lstatSync",
  "access",
  "accessSync",
  "rename",
  "renameSync",
]);

export function detectPathTraversal(
  sourceFile: SourceFile,
  options: HandlerScanOptions = {}
): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile, options)) {
    if (!handlerBody || paramNames.length === 0) continue;

    const tainted = getTaintedNames(handlerBody, paramNames);
    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();
      const funcName = callText.split(".").pop() ?? callText;

      if (!FS_SINKS.has(funcName)) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const pathArg = args[0];
      const argText = pathArg.getText();
      const matched = findTaintedReaching(pathArg, tainted);

      if (!matched) continue;

      const hasSafeWrapper =
        argText.startsWith("path.resolve") ||
        argText.startsWith("path.normalize") ||
        argText.startsWith("resolve(") ||
        argText.startsWith("normalize(");

      if (!hasSafeWrapper) {
        const lineNum = call.getStartLineNumber();
        const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());

        findings.push({
          rule: "mcp-path-traversal",
          severity: "high",
          cwe: "CWE-22",
          file: filePath,
          line: lineNum,
          column,
          message: `User-controlled path flows to ${funcName}() without proper boundary validation`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Use path.resolve(BASE_DIR, userInput) and verify the result starts with BASE_DIR before accessing the filesystem.",
          confidence: "high",
          taintChain: [...matched.chain, `${funcName}() (line ${lineNum})`],
        });
      }
    }
  }

  return findings;
}
