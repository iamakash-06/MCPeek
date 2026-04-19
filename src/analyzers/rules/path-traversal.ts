import { SourceFile, SyntaxKind, Node } from "ts-morph";
import type { Finding } from "../../types.js";
import { findMCPToolHandlers } from "./command-injection.js";

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


export function detectPathTraversal(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  const toolHandlers = findMCPToolHandlers(sourceFile);

  for (const { paramNames, handlerBody } of toolHandlers) {
    if (!handlerBody || paramNames.length === 0) continue;

    const calls = handlerBody.getDescendantsOfKind(SyntaxKind.CallExpression);

    for (const call of calls) {
      const callText = call.getExpression().getText();
      const funcName = callText.split(".").pop() ?? callText;

      if (!FS_SINKS.has(funcName)) continue;

      const args = call.getArguments();
      if (args.length === 0) continue;

      const pathArg = args[0];
      const argText = pathArg.getText();

      const usesHandlerParam = paramNames.some(
        (p) => argText.includes(p) || containsIdentifier(pathArg, p)
      );

      if (!usesHandlerParam) continue;

      // Check if the path argument is wrapped in path.resolve or similar
      const hasSafeWrapper =
        argText.startsWith("path.resolve") ||
        argText.startsWith("path.normalize") ||
        argText.startsWith("resolve(") ||
        argText.startsWith("normalize(");

      // Check for boundary validation nearby (startsWith check in same block)
      const blockText = handlerBody.getText();
      const hasBoundaryCheck =
        blockText.includes(".startsWith(") ||
        blockText.includes("startsWith(") ||
        blockText.includes("path.relative");

      if (!hasSafeWrapper || !hasBoundaryCheck) {
        const lineNum = call.getStartLineNumber();
        const severity = !hasSafeWrapper ? "high" : "medium";

        findings.push({
          rule: "mcp-path-traversal",
          severity,
          cwe: "CWE-22",
          file: filePath,
          line: lineNum,
          column: 1,
          message: `User-controlled path flows to ${funcName}() without proper boundary validation`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Use path.resolve(BASE_DIR, userInput) and verify the result starts with BASE_DIR before accessing the filesystem.",
          confidence: "high",
        });
      }
    }
  }

  return findings;
}

function containsIdentifier(node: Node, name: string): boolean {
  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((id) => id.getText() === name);
}

function extractSnippet(
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
