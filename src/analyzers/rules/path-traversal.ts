import { SourceFile, SyntaxKind, Node, Identifier } from "ts-morph";
import type { Finding } from "../../types.js";
import { getTaintedNames } from "../taint-tracker.js";
import { findMCPToolHandlers } from "../mcp-handler.js";
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

export function detectPathTraversal(sourceFile: SourceFile): Finding[] {
  const findings: Finding[] = [];
  const filePath = sourceFile.getFilePath();

  for (const { paramNames, handlerBody } of findMCPToolHandlers(sourceFile)) {
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

      const matchedName = [...tainted.keys()].find(
        (p) => argText.includes(p) || containsIdentifier(pathArg, p)
      );

      if (matchedName === undefined) continue;

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
        const chain = tainted.get(matchedName)!;
        const { column } = sourceFile.getLineAndColumnAtPos(call.getStart());
        const severity = !hasSafeWrapper ? "high" : "medium";

        findings.push({
          rule: "mcp-path-traversal",
          severity,
          cwe: "CWE-22",
          file: filePath,
          line: lineNum,
          column,
          message: `User-controlled path flows to ${funcName}() without proper boundary validation`,
          evidence: extractSnippet(sourceFile, lineNum, 3),
          remediation:
            "Use path.resolve(BASE_DIR, userInput) and verify the result starts with BASE_DIR before accessing the filesystem.",
          confidence: "high",
          taintChain: [...chain, `${funcName}() (line ${lineNum})`],
        });
      }
    }
  }

  return findings;
}

function containsIdentifier(node: Node, name: string): boolean {
  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((id: Identifier) => id.getText() === name);
}
